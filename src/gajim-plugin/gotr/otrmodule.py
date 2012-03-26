#!/usr/bin/env python
# -*- coding: utf-8 -*-
##    otrmodule.py
##
## Copyright 2008-2012 Kjell Braden <afflux@pentabarf.de>
##
## This file is part of Gajim.
##
## Gajim is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published
## by the Free Software Foundation; version 3 only.
##
## Gajim is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with Gajim.  If not, see <http://www.gnu.org/licenses/>.
##


'''
Off-The-Record encryption plugin.

:author: Kjell self.Braden <kb.otr@pentabarf.de>
:since: 20 May 2011
:copyright: Copyright (2011) Kjell Braden <kb.otr@pentabarf.de>
:license: GPL
'''

MINVERSION = (1,0,0,'beta4')
IGNORE = True
PASS = False

DEFAULTFLAGS = {
            'ALLOW_V1':False,
            'ALLOW_V2':True,
            'REQUIRE_ENCRYPTION':False,
            'SEND_TAG':True,
            'WHITESPACE_START_AKE':True,
            'ERROR_START_AKE':True,
        }

MMS = 1024
PROTOCOL = 'xmpp'

enc_tip = 'A private chat session <i>is established</i> to this contact ' \
        'with this fingerprint'
unused_tip = 'A private chat session is established to this contact using ' \
        '<i>another</i> fingerprint'
ended_tip = 'The private chat session to this contact has <i>ended</i>'
inactive_tip = 'Communication to this contact is currently ' \
        '<i>unencrypted</i>'

import os
import time

import common.xmpp
from common import gajim
from common import ged
from common.connection_handlers_events import MessageOutgoingEvent
from plugins import GajimPlugin
from message_control import TYPE_CHAT, MessageControl
from plugins.helpers import log_calls, log
from plugins.plugin import GajimPluginException

import ui


import pickle
HAS_POTR = True
try:
    import potr
    if not hasattr(potr, 'VERSION') or potr.VERSION < MINVERSION:
        raise ImportError('old / unsupported python-otr version')
except ImportError:
    HAS_POTR = False

def get_jid_from_fjid(fjid):
    return gajim.get_room_and_nick_from_fjid(fjid)[0]

class GajimContext(potr.context.Context):
    # self.peer is fjid
    # self.jid does not contain resource
    __slots__ = ['smpWindow', 'jid']

    def __init__(self, account, peer):
        super(GajimContext, self).__init__(account, peer)
        self.jid = get_jid_from_fjid(peer)
        self.trustName = self.jid
        self.smpWindow = ui.ContactOtrSmpWindow(self)

    def inject(self, msg, appdata=None):
        log.debug('inject(appdata=%s)', appdata)
        msg = unicode(msg)
        account = self.user.accountname

        stanza = common.xmpp.Message(to=self.peer, body=msg, typ='chat')
        if appdata and 'session' in appdata:
            session = appdata['session']
            stanza.setThread(session.thread_id)
        gajim.connections[account].connection.send(stanza, now=True)
        return

    def setState(self, newstate):
        if self.state == potr.context.STATE_ENCRYPTED:
            # we were encrypted
            if newstate == potr.context.STATE_ENCRYPTED:
                # and are still -> it's just a refresh
                OtrPlugin.gajim_log(
                        _('Private conversation with %s refreshed.') % self.peer,
                        self.user.accountname, self.peer)
            elif newstate == potr.context.STATE_FINISHED:
                # and aren't anymore -> other side disconnected
                OtrPlugin.gajim_log(_('%s has ended his/her private '
                        'conversation with you. You should do the same.')
                        % self.peer, self.user.accountname, self.peer)
        else:
            if newstate == potr.context.STATE_ENCRYPTED:
                # we are now encrypted
                trust = self.getCurrentTrust()
                if trust is None:
                    fpr = str(self.getCurrentKey())
                    OtrPlugin.gajim_log(_('New fingerprint for %(peer)s: %(fpr)s')
                            % {'peer': self.peer, 'fpr': fpr},
                            self.user.accountname, self.peer)
                    self.setCurrentTrust('')
                trustStr = 'authenticated' if bool(trust) else '*unauthenticated*'
                OtrPlugin.gajim_log(
                    _('%(trustStr)s secured OTR conversation with %(peer)s started')
                    % {'trustStr': trustStr, 'peer': self.peer},
                    self.user.accountname, self.peer)

        if self.state != potr.context.STATE_PLAINTEXT and \
                newstate == potr.context.STATE_PLAINTEXT:
            # we are now plaintext
            OtrPlugin.gajim_log(
                    _('Private conversation with %s lost.') % self.peer,
                    self.user.accountname, self.peer)

        super(GajimContext, self).setState(newstate)
        OtrPlugin.update_otr(self.peer, self.user.accountname)
        self.user.plugin.update_context_list()

    def getPolicy(self, key):
        ret = self.user.plugin.get_flags(self.user.accountname, self.jid)[key]
        log.debug('getPolicy(key=%s) = %s', key, ret)
        return ret

class GajimOtrAccount(potr.context.Account):
    contextclass = GajimContext
    def __init__(self, plugin, accountname):
        global PROTOCOL, MMS
        self.plugin = plugin
        self.accountname = accountname
        name = gajim.get_jid_from_account(accountname)
        super(GajimOtrAccount, self).__init__(name, PROTOCOL, MMS)
        self.keyFilePath = os.path.join(gajim.gajimpaths.data_root, accountname)

    def dropPrivkey(self):
        try:
            os.remove(self.keyFilePath + '.key3')
        except IOError, e:
            if e.errno != 2:
                log.exception('IOError occurred when removing key file for %s',
                        self.name)
        self.privkey = None

    def loadPrivkey(self):
        try:
            with open(self.keyFilePath + '.key3', 'rb') as keyFile:
                return potr.crypt.PK.parsePrivateKey(keyFile.read())[0]
        except IOError, e:
            if e.errno != 2:
                log.exception('IOError occurred when loading key file for %s',
                        self.name)
        return None

    def savePrivkey(self):
        try:
            with open(self.keyFilePath + '.key3', 'wb') as keyFile:
                keyFile.write(self.getPrivkey().serializePrivateKey())
        except IOError, e:
            log.exception('IOError occurred when loading key file for %s',
                    self.name)

    def loadTrusts(self, newCtxCb=None):
        ''' load the fingerprint trustdb '''
        # it has the same format as libotr, therefore the
        # redundant account / proto field
        try:
            with open(self.keyFilePath + '.fpr', 'r') as fprFile:
                for line in fprFile:
                    ctx, acc, proto, fpr, trust = line[:-1].split('\t')

                    if acc != self.name or proto != PROTOCOL:
                        continue

                    jid = get_jid_from_fjid(ctx)
                    self.setTrust(jid, fpr, trust)
        except IOError, e:
            if e.errno != 2:
                log.exception('IOError occurred when loading fpr file for %s',
                        self.name)

    def saveTrusts(self):
        try:
            with open(self.keyFilePath + '.fpr', 'w') as fprFile:
                for uid, trusts in self.trusts.iteritems():
                    for fpr, trustVal in trusts.iteritems():
                        fprFile.write('\t'.join(
                                (uid, self.name, PROTOCOL, fpr, trustVal)))
                        fprFile.write('\n')
        except IOError, e:
            log.exception('IOError occurred when loading fpr file for %s',
                    self.name)


def otr_dialog_destroy(widget, *args, **kwargs):
    widget.destroy()

class OtrPlugin(GajimPlugin):
    otr = None
    def init(self):

        self.description = _('See http://www.cypherpunks.ca/otr/')
        self.us = {}
        self.config_dialog = ui.OtrPluginConfigDialog(self)
        self.events_handlers = {}
        self.events_handlers['message-received'] = (ged.PRECORE,
                self.handle_incoming_msg)
        self.events_handlers['message-outgoing'] = (ged.OUT_PRECORE,
                self.handle_outgoing_msg)

        self.gui_extension_points = {
                    'chat_control' : (self.cc_connect, self.cc_disconnect)
                }

        for acc in gajim.contacts.get_accounts():
            self.us[acc] = GajimOtrAccount(self, acc)
            self.us[acc].loadTrusts()

            acc = str(acc)
            if acc not in self.config or None not in self.config[acc]:
                self.config[acc] = {None:DEFAULTFLAGS.copy()}
        self.update_context_list()

    @log_calls('OtrPlugin')
    def activate(self):
        if not HAS_POTR:
            raise GajimPluginException('python-otr is missing!')
        if not hasattr(potr, 'VERSION') or potr.VERSION < MINVERSION:
            raise GajimPluginException('old / unsupported python-otr version')

    def get_otr_status(self, account, contact):
        ctx = self.us[account].getContext(contact.get_full_jid())

        finished = ctx.state == potr.context.STATE_FINISHED
        encrypted = finished or ctx.state == potr.context.STATE_ENCRYPTED
        trusted = encrypted and bool(ctx.getCurrentTrust())
        return (encrypted, trusted, finished)

    def cc_connect(self, cc):
        def update_otr(print_status=False):
            enc_status, authenticated, finished = \
                    self.get_otr_status(cc.account, cc.contact)
            otr_status_text = ''

            if finished:
                otr_status_text = u'finished OTR connection'
            elif authenticated:
                otr_status_text = u'authenticated secure OTR connection'
            elif enc_status:
                otr_status_text = u'*unauthenticated* secure OTR connection'

            cc._show_lock_image(enc_status, u'OTR', enc_status, True,
                    authenticated)
            if print_status and otr_status_text:
                cc.print_conversation_line(u'[OTR] %s' % otr_status_text,
                        'status', '', None)
        cc.update_otr = update_otr
        cc.update_otr(True)

        # hijack authentication button with our submenu
        def authbutton_cb(widget):
            if not cc.gpg_is_active and not (cc.session and
            cc.session.enable_encryption):
                ui.get_otr_submenu(self, cc).get_submenu().popup(None,
                        None, None, 0, 0)
            else:
                cc._on_authentication_button_clicked(cc, widget)
        self.overwrite_handler(cc, cc.authentication_button, authbutton_cb)

        # hijack context menu
        cc.orig_prepare_context_menu = cc.prepare_context_menu
        def inject_menu(hide_buttonbar_items=False):
            menu = cc.orig_prepare_context_menu(hide_buttonbar_items)
            menu.insert(ui.get_otr_submenu(self, cc), 8)
            return menu
        cc.prepare_context_menu = inject_menu

    def cc_disconnect(self, cc):
        try:
            self.overwrite_handler(cc, cc.authentication_button,
                    cc._on_authentication_button_clicked)
            cc.prepare_context_menu = cc.orig_prepare_context_menu
            del cc.update_otr
        except AttributeError:
            pass

    def menu_settings_cb(self, item, control):
        ctx = self.us[control.account].getContext(control.contact.get_full_jid())
        dlg = ui.ContactOtrWindow(self, ctx)
        dlg.run()
        dlg.destroy()

    def menu_start_cb(self, item, control):
        gajim.nec.push_outgoing_event(MessageOutgoingEvent(None,
                account=control.account, jid=control.contact.jid,
                message=u'?OTRv?', type_='chat',
                resource=control.contact.resource, is_loggable=False))

    def menu_end_cb(self, item, control):
        fjid = control.contact.get_full_jid()
        thread_id = control.session.thread_id if control.session else None

        self.us[control.account].getContext(fjid).disconnect(
                appdata={'session':control.session})

    def menu_smp_cb(self, item, control):
        ctx = self.us[control.account].getContext(control.contact.get_full_jid())
        ctx.smpWindow.show(False)

    @staticmethod
    def overwrite_handler(window, control, handler):
        for id_, v in window.handlers.iteritems():
            if v == control:
                break
        else:
            raise LookupError

        del window.handlers[id_]
        control.disconnect(id_)
        id_ = control.connect('clicked', handler)
        window.handlers[id_] = control

    def set_flags(self, value, account=None, contact=None):
        if isinstance(account, unicode):
            account = account.encode()

        if account not in self.config:
            self.config[account] = {None:DEFAULTFLAGS.copy()}

        if account is None and contact is not None:
            # don't set per-contact options without account
            raise Exception("can't set contact flags without account")

        config = self.config[account]
        config[contact] = value

        self.config[account] = config

    def get_flags(self, account=None, contact=None, fallback=True):
        if isinstance(account, unicode):
            account = account.encode()

        setting = DEFAULTFLAGS.copy()
        if account in self.config:
            setting.update(self.config[account][None])
            if contact in self.config[account] \
                    and self.config[account][contact] is not None:
                setting.update(self.config[account][contact])
            elif not fallback:
                return None
        return setting

    def update_context_list(self):
        self.config_dialog.fpr_model.clear()
        for us in self.us.itervalues():
            usedFpr = set()
            for fjid, ctx in us.ctxs.iteritems():
                # get active contexts first
                key = ctx.getCurrentKey()
                if not key:
                    continue
                fpr = key.cfingerprint()
                usedFpr.add(fpr)

                human_hash = potr.human_hash(fpr)
                trust = bool(us.getTrust(ctx.trustName, fpr))

                if ctx.state == potr.context.STATE_ENCRYPTED:
                    state = "encrypted"
                    tip = enc_tip
                elif ctx.state == potr.context.STATE_FINISHED:
                    state = "finished"
                    tip = ended_tip
                else:
                    state = 'inactive'
                    tip = inactive_tip

                self.config_dialog.fpr_model.append((fjid, state, trust,
                        '<tt>%s</tt>' % human_hash, us.name, tip, fpr))

            for uid, trusts in us.trusts.iteritems():
                for fpr, trust in trusts.iteritems():
                    if fpr in usedFpr:
                        continue

                    state = 'inactive'
                    tip = inactive_tip

                    human_hash = potr.human_hash(fpr)

                    self.config_dialog.fpr_model.append((uid, state, bool(trust),
                            '<tt>%s</tt>' % human_hash, us.name, tip, fpr))

    @classmethod
    def gajim_log(cls, msg, account, fjid, no_print=False,
    is_status_message=True, thread_id=None):
        if not isinstance(fjid, unicode):
            fjid = unicode(fjid)
        if not isinstance(account, unicode):
            account = unicode(account)

        resource = gajim.get_resource_from_jid(fjid)
        jid = gajim.get_jid_without_resource(fjid)
        tim = time.localtime()

        if is_status_message is True:
            if not no_print:
                ctrl = cls.get_control(fjid, account)
                if ctrl:
                    ctrl.print_conversation_line(u'[OTR] %s' % msg, 'status',
                            '', None)
            id = gajim.logger.write('chat_msg_recv', fjid,
                    message=u'[OTR: %s]' % msg, tim=tim)
            # gajim.logger.write() only marks a message as unread (and so
            # only returns an id) when fjid is a real contact (NOT if it's a
            # GC private chat)
            if id:
                gajim.logger.set_read_messages([id])
        else:
            session = gajim.connections[account].get_or_create_session(fjid,
                    thread_id)
            session.received_thread_id |= bool(thread_id)
            session.last_receive = time.time()

            if not session.control:
                # look for an existing chat control without a session
                ctrl = cls.get_control(fjid, account)
                if ctrl:
                    session.control = ctrl
                    session.control.set_session(session)

            msg_id = gajim.logger.write('chat_msg_recv', fjid,
                    message=u'[OTR: %s]' % msg, tim=tim)
            session.roster_message(jid, msg, tim=tim, msg_id=msg_id,
                    msg_type='chat', resource=resource)

    @classmethod
    def update_otr(cls, user, acc, print_status=False):
        ctrl = cls.get_control(user, acc)
        if ctrl:
            ctrl.update_otr(print_status)

    @staticmethod
    def get_control(fjid, account):
        # first try to get the window with the full jid
        ctrl = gajim.interface.msg_win_mgr.get_control(fjid, account)
        if ctrl:
            # got one, be happy
            return ctrl

        # otherwise try without the resource
        ctrl = gajim.interface.msg_win_mgr.get_control(
                gajim.get_jid_without_resource(fjid), account)
        # but only use it when it's not a GC window
        if ctrl and ctrl.TYPE_ID == TYPE_CHAT:
            return ctrl

    def handle_incoming_msg(self, event):
        ctx = None
        account = event.conn.name
        accjid = gajim.get_jid_from_account(account)

        if event.encrypted is not False or not event.stanza.getTag('body') \
        or not isinstance(event.stanza.getBody(), unicode):
            return PASS

        try:
            ctx = self.us[account].getContext(event.fjid)
            msgtxt, tlvs = ctx.receiveMessage(event.msgtxt,
                            appdata={'session':event.session})
        except potr.context.UnencryptedMessage, e:
            tlvs = []
            msgtxt = _('The following message received from %(jid)s was '
                    '*not encrypted*: [%(error)s]') % {'jid': event.fjid,
                    'error': e.args[0]}
        except potr.context.NotEncryptedError, e:
            self.gajim_log(_('The encrypted message received from %s is '
                    'unreadable, as you are not currently communicating '
                    'privately') % event.fjid, account, event.fjid)
            return IGNORE
        except potr.context.ErrorReceived, e:
            self.gajim_log(_('We received the following OTR error '
                    'message from %(jid)s: [%(error)s]') % {'jid': event.fjid,
                    'error': e.args[0].error})
            return IGNORE
        except RuntimeError, e:
            self.gajim_log(_('The following error occurred when trying to '
                    'decrypt a message from %(jid)s: [%(error)s]') % {
                    'jid': event.fjid, 'error': e},
                    account, event.fjid)
            return IGNORE

        if ctx is not None:
            ctx.smpWindow.handle_tlv(tlvs)
        if not msgtxt:
            return IGNORE

        event.msgtxt = unicode(msgtxt)
        event.stanza.setBody(event.msgtxt)

        html_node = event.stanza.getTag('html')
        if html_node:
            event.stanza.delChild(html_node)

        return PASS

    def handle_outgoing_msg(self, event):
        if hasattr(event, 'otrmessage'):
            return PASS

        xep_200 = bool(event.session) and event.session.enable_encryption
        if xep_200 or not event.message:
            return PASS

        if event.session:
            fjid = event.session.get_to()
        else:
            fjid = event.jid
            if event.resource:
                fjid += '/' + event.resource

        try:
            newmsg = self.us[event.account].getContext(fjid).sendMessage(
                    potr.context.FRAGMENT_SEND_ALL_BUT_LAST, event.message,
                    appdata={'session':event.session})
        except potr.context.NotEncryptedError, e:
            if e.args[0] == potr.context.EXC_FINISHED:
                self.gajim_log(_('Your message was not send. Either end '
                    'your private conversation, or restart it'), event.account,
                    fjid)
                return IGNORE
            else:
                raise e
        event.message = newmsg

        return PASS

## TODO:
##  - disconnect ctxs on disconnect
