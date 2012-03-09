#!/usr/bin/env python
# -*- coding: utf-8 -*-
##    ui.py
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
import gobject
import gtk
from common import gajim
from plugins.gui import GajimPluginConfigDialog

import otrmodule
import potr


class OtrPluginConfigDialog(GajimPluginConfigDialog):
    def init(self):
        self.GTK_BUILDER_FILE_PATH = \
                self.plugin.local_file_path('config_dialog.ui')
        self.B = gtk.Builder()
        self.B.set_translation_domain('gajim_plugins')
        self.B.add_from_file(self.GTK_BUILDER_FILE_PATH)

        self.fpr_model = gtk.ListStore(gobject.TYPE_STRING, gobject.TYPE_STRING,
                gobject.TYPE_BOOLEAN, gobject.TYPE_STRING, gobject.TYPE_STRING,
                gobject.TYPE_STRING, gobject.TYPE_STRING)

        self.otr_account_store = self.B.get_object('account_store')

        for account in sorted(gajim.contacts.get_accounts()):
            self.otr_account_store.append(row=(account,))

        fpr_view = self.B.get_object('fingerprint_view')
        fpr_view.set_model(self.fpr_model)
        fpr_view.get_selection().set_mode(gtk.SELECTION_MULTIPLE)

        if len(self.otr_account_store) > 0:
            self.B.get_object('account_combobox').set_active(0)

        self.child.pack_start(self.B.get_object('notebook1'))

        self.flags = dict()
        flagList = (
            ('ALLOW_V2', 'enable_check'),
            ('SEND_TAG', 'advertise_check'),
            ('WHITESPACE_START_AKE', 'autoinitiate_check'),
            ('REQUIRE_ENCRYPTION', 'require_check')
        )
        for flagName, checkBoxName in flagList:
            self.flags[flagName] = self.B.get_object(checkBoxName)

        self.B.connect_signals(self)

    def on_run(self):
        self.plugin.update_context_list()
        self.account_combobox_changed_cb(self.B.get_object('account_combobox'))

    def flags_toggled_cb(self, button):
        if button == self.B.get_object('enable_check'):
            new_status = button.get_active()
            self.B.get_object('advertise_check').set_sensitive(new_status)
            self.B.get_object('autoinitiate_check').set_sensitive(new_status)
            self.B.get_object('require_check').set_sensitive(new_status)

            if new_status is False:
                self.B.get_object('advertise_check').set_active(False)
                self.B.get_object('autoinitiate_check').set_active(False)
                self.B.get_object('require_check').set_active(False)

        box = self.B.get_object('account_combobox')
        active = box.get_active()
        if active > -1:
            account = self.otr_account_store[active][0]

            flagValues = {}
            for key, box in self.flags.iteritems():
                flagValues[key] = box.get_active()
            self.plugin.set_flags(flagValues, account)

    def account_combobox_changed_cb(self, box, *args):
        fpr_label = self.B.get_object('fingerprint_label')
        regen_button = self.B.get_object('regenerate_button')

        active = box.get_active()
        fpr = '-------- -------- -------- -------- --------'
        try:
            if active > -1:
                regen_button.set_sensitive(True)
                account = self.otr_account_store[active][0]

                otr_flags = self.plugin.get_flags(account)
                for key, box in self.flags.iteritems():
                    box.set_active(otr_flags[key])

                fpr = str(self.plugin.us[account].getPrivkey(autogen=False))
                regen_button.set_label('Regenerate')
            else:
                regen_button.set_sensitive(False)
        except LookupError, e:
            # Account not found, no private key available - display the
            # empty one
            regen_button.set_label('Generate')
        finally:
            self.B.get_object('fingerprint_label').set_markup('<tt>%s</tt>'%fpr)

    def forget_button_clicked_cb(self, button, *args):
        accounts = {}
        for acc in gajim.connections.iterkeys():
            accounts[gajim.get_jid_from_account(acc)] = acc

        tw = self.B.get_object('fingerprint_view')

        mod, paths = tw.get_selection().get_selected_rows()

        for path in paths:
            it = mod.get_iter(path)
            user, human_fpr, a, fpr = mod.get(it, 0, 3, 4, 6)

            dlg = gtk.Dialog('Confirm removal of fingerprint', self,
                    gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
                        (gtk.STOCK_YES, gtk.RESPONSE_YES,
                        gtk.STOCK_NO, gtk.RESPONSE_NO)
                    )
            l = gtk.Label()
            l.set_markup('Are you sure you want remove the following '
                    'fingerprint for the contact %s on the account %s?'
                    '\n\n%s' % (user, a, human_fpr))
            l.set_line_wrap(True)
            dlg.vbox.pack_start(l)
            dlg.show_all()

            if dlg.run() == gtk.RESPONSE_YES:
                ctx = self.plugin.us[accounts[a]].getContext(user)
                ctx.removeFingerprint(fpr)
            dlg.destroy()
            self.plugin.us[accounts[a]].saveTrusts()

        self.plugin.update_context_list()

    def verify_button_clicked_cb(self, button, *args):
        accounts = {}
        for acc in gajim.connections.iterkeys():
            accounts[gajim.get_jid_from_account(acc)] = acc

        tw = self.B.get_object('fingerprint_view')

        mod, paths = tw.get_selection().get_selected_rows()

        # open the window for the first selected row
        for path in paths[0:1]:
            it = mod.get_iter(path)
            fjid, fpr, a = mod.get(it, 0, 6, 4)

            ctx = self.plugin.us[accounts[a]].getContext(fjid)

            dlg = ContactOtrWindow(self.plugin, ctx, fpr=fpr, parent=self)
            dlg.run()
            dlg.destroy()
            break

    def regenerate_button_clicked_cb(self, button, *args):
        box = self.B.get_object('account_combobox')
        active = box.get_active()
        if active > -1:
            account = self.otr_account_store[active][0]
            button.set_sensitive(False)
            try:
                self.plugin.us[account].getPrivkey(autogen=False)
                self.plugin.us[account].dropPrivkey()
            except LookupError:
                pass
            self.plugin.us[account].getPrivkey(autogen=True)
            self.account_combobox_changed_cb(box, *args)
            button.set_sensitive(True)


import gtkgui_helpers
from common import gajim

our_fp_text = _('Your fingerprint:\n' \
    '<span weight="bold" face="monospace">%s</span>')
their_fp_text = _('Purported fingerprint for %(jid)s:\n' \
    '<span weight="bold" face="monospace">%(fp)s</span>')

another_q = _('You may want to authenticate your buddy as well by asking'\
        'your own question.')
smp_query = _('<b>%s is trying to authenticate you using a secret only known '\
        'to him/her and you.</b>')
smp_q_query = _('<b>%s has chosen a question for you to answer to '\
        'authenticate yourself:</b>')
enter_secret = _('Please enter your secret below.')

smp_init = _('<b>You are trying to authenticate %s using a secret only known ' \
        'to him/her and yourself.</b>')
choose_q = _('You can choose a question as a hint for your buddy below.')

class ContactOtrSmpWindow:
    def gw(self, n):
        return self.xml.get_object(n)

    def __init__(self, ctx):
        self.question = None
        self.ctx = ctx
        self.account = ctx.user.accountname

        self.plugin = ctx.user.plugin

        self.GTK_BUILDER_FILE_PATH = \
                self.plugin.local_file_path('contact_otr_window.ui')
        self.xml = gtk.Builder()
        self.xml.set_translation_domain('gajim_plugins')
        self.xml.add_from_file(self.GTK_BUILDER_FILE_PATH)

        self.window = self.gw('otr_smp_window')
        self.window.set_title(_('OTR settings for %s') % ctx.peer)

        # the lambda thing is an anonymous helper that just discards the
        # parameters and calls hide_on_delete on clicking the window's
        # close button
        self.window.connect('delete-event', lambda d,o:
                self.window.hide_on_delete())

        self.gw('smp_cancel_button').connect('clicked', self._on_destroy)
        self.gw('smp_ok_button').connect('clicked', self._apply)
        self.gw('qcheckbutton').connect('toggled', self._toggle)

        self.gw('qcheckbutton').set_no_show_all(False)
        self.gw('qentry').set_no_show_all(False)
        self.gw('desclabel2').set_no_show_all(False)

    def _toggle(self, w, *args):
        self.gw('qentry').set_sensitive(w.get_active())

    def show(self, response):
        self.smp_running = False
        self.finished = False

        self.gw('smp_cancel_button').set_sensitive(True)
        self.gw('smp_ok_button').set_sensitive(True)
        self.gw('progressbar').set_fraction(0)
        self.gw('secret_entry').set_text('')

        self.response = response
        self.window.show_all()
        if response:
            self.gw('qcheckbutton').set_sensitive(False)
            if self.question is None:
                self.gw('qcheckbutton').set_active(False)
                self.gw('qcheckbutton').hide()
                self.gw('qentry').hide()
                self.gw('desclabel2').hide()
                self.gw('qcheckbutton').set_sensitive(False)
                self.gw('desclabel1').set_markup((smp_query % self.ctx.peer)
                        + ' ' + enter_secret)
            else:
                self.gw('qcheckbutton').set_active(True)
                self.gw('qcheckbutton').show()
                self.gw('qentry').show()
                self.gw('qentry').set_sensitive(True)
                self.gw('qentry').set_editable(False)
                self.gw('desclabel2').show()
                self.gw('qentry').set_text(self.question)

                self.gw('desclabel1').set_markup(smp_q_query % self.ctx.peer)
                self.gw('desclabel2').set_markup(enter_secret)
        else:
            self.gw('qcheckbutton').show()
            self.gw('qcheckbutton').set_active(True)
            self.gw('qcheckbutton').set_mode(True)
            self.gw('qcheckbutton').set_sensitive(True)
            self.gw('qentry').set_sensitive(True)
            self.gw('qentry').show()
            self.gw('qentry').set_text("")

            self.gw('qentry').set_editable(True)
            self.gw('qentry').set_sensitive(True)

            self.gw('desclabel2').show()
            self.gw('desclabel1').set_markup((smp_init % self.ctx.peer) + ' '
                    + choose_q)
            self.gw('desclabel2').set_markup(enter_secret)

    def _abort(self, text=None, appdata=None):
        self.smp_running = False

        self.ctx.smpAbort(appdata=appdata)
        if text:
            self.plugin.gajim_log(text, self.account, self.ctx.peer)

    def _finish(self, text):
        self.smp_running = False
        self.finished = True

        self.gw('qcheckbutton').set_active(False)
        self.gw('qcheckbutton').hide()
        self.gw('qentry').hide()
        self.gw('desclabel2').hide()

        self.gw('qcheckbutton').set_sensitive(False)
        self.gw('smp_cancel_button').set_sensitive(False)
        self.gw('smp_ok_button').set_sensitive(True)
        self.gw('progressbar').set_fraction(1)
        self.plugin.gajim_log(text, self.account, self.ctx.peer)
        self.gw('desclabel1').set_markup(text)

        self.plugin.update_otr(self.ctx.peer, self.account, True)
        self.ctx.user.saveTrusts()
        self.plugin.update_context_list()

    def get_tlv(self, tlvs, check):
        for tlv in tlvs:
            if isinstance(tlv, check):
                return tlv
        return None

    def handle_tlv(self, tlvs):
        if tlvs:
            is1qtlv = self.get_tlv(tlvs, potr.proto.SMP1QTLV)
            # check for TLV_SMP_ABORT or state = CHEATED
            if not self.ctx.smpIsValid():
                self._abort()
                self._finish(_('SMP verifying aborted'))

            # check for TLV_SMP1
            elif self.get_tlv(tlvs, potr.proto.SMP1TLV):
                self.question = None
                self.show(True)
                self.gw('progressbar').set_fraction(0.3)

            # check for TLV_SMP1Q
            elif is1qtlv:
                self.question = is1qtlv.msg
                self.show(True)
                self.gw('progressbar').set_fraction(0.3)

            # check for TLV_SMP2
            elif self.get_tlv(tlvs, potr.proto.SMP2TLV):
                self.gw('progressbar').set_fraction(0.6)

            # check for TLV_SMP3
            elif self.get_tlv(tlvs, potr.proto.SMP3TLV):
                if self.ctx.smpIsSuccess():
                    text = _('SMP verifying succeeded')
                    if self.question is not None:
                        text += ' '+another_q
                    self._finish(text)
                else:
                    self._finish(_('SMP verifying failed'))

            # check for TLV_SMP4
            elif self.get_tlv(tlvs, potr.proto.SMP4TLV):
                if self.ctx.smpIsSuccess():
                    text = _('SMP verifying succeeded')
                    if self.question is not None:
                        text += ' '+another_q
                    self._finish(text)
                else:
                    self._finish(_('SMP verifying failed'))

    def _on_destroy(self, widget):
        if self.smp_running:
            self._abort(_('user aborted SMP authentication'))
        self.window.hide_all()

    def _apply(self, widget, appdata=None):
        if self.finished:
            self.window.hide_all()
            return
        secret = self.gw('secret_entry').get_text()
        if self.response:
            self.ctx.smpGotSecret(secret, appdata=appdata)
        else:
            if self.gw('qcheckbutton').get_active():
                qtext = self.gw('qentry').get_text()
                self.ctx.smpInit(secret, question=qtext, appdata=appdata)
            else:
                self.ctx.smpInit(secret, appdata=appdata)
            self.gw('progressbar').set_fraction(0.3)
        self.smp_running = True
        widget.set_sensitive(False)

class ContactOtrWindow(gtk.Dialog):
    def gw(self, n):
        return self.xml.get_object(n)

    def __init__(self, plugin, ctx, fpr=None, parent=None):
        fjid = ctx.peer
        gtk.Dialog.__init__(self, title=_('OTR settings for %s') % fjid,
                parent=parent,
                flags=gtk.DIALOG_DESTROY_WITH_PARENT,
                buttons=(gtk.STOCK_CANCEL, gtk.RESPONSE_REJECT,
                gtk.STOCK_OK, gtk.RESPONSE_ACCEPT))

        self.ctx = ctx
        self.fjid = fjid
        self.jid = gajim.get_room_and_nick_from_fjid(self.fjid)[0]
        self.account = ctx.user.accountname
        self.fpr = fpr
        self.plugin = plugin

        if self.fpr is None:
            key = self.ctx.getCurrentKey()
            if key is not None:
                self.fpr = key.cfingerprint()

        self.GTK_BUILDER_FILE_PATH = \
                self.plugin.local_file_path('contact_otr_window.ui')
        self.xml = gtk.Builder()
        self.xml.set_translation_domain('gajim_plugins')
        self.xml.add_from_file(self.GTK_BUILDER_FILE_PATH)
        self.notebook = self.gw('otr_settings_notebook')
        self.child.pack_start(self.notebook)

        self.connect('response', self.on_response)
        self.gw('otr_default_checkbutton').connect('toggled',
                self._otr_default_checkbutton_toggled)

        # always set the label containing our fingerprint
        self.gw('our_fp_label').set_markup(our_fp_text % ctx.user.getPrivkey())

        if self.fpr is None:
            # make the fingerprint widgets insensitive
            # when not encrypted
            for widget in self.gw('otr_fp_vbox').get_children():
                widget.set_sensitive(False)
            # show that the fingerprint is unknown
            self.gw('their_fp_label').set_markup(their_fp_text % {
                    'jid': self.fjid, 'fp': _('unknown')})
            self.gw('verified_combobox').set_active(-1)
        else:
            # make the fingerprint widgets sensitive when encrypted
            for widget in self.gw('otr_fp_vbox').get_children():
                widget.set_sensitive(True)
            # show their fingerprint
            fp = potr.human_hash(self.fpr)
            self.gw('their_fp_label').set_markup(their_fp_text % {
                    'jid': self.fjid, 'fp': fp})
            # set the trust combobox
            if ctx.getCurrentTrust():
                self.gw('verified_combobox').set_active(1)
            else:
                self.gw('verified_combobox').set_active(0)

        otr_flags = self.plugin.get_flags(self.account, self.jid, fallback=False)

        if otr_flags is not None:
            self.gw('otr_default_checkbutton').set_active(0)
            for w in self.gw('otr_settings_vbox').get_children():
                w.set_sensitive(True)
        else:
            # per-user settings not available,
            # using default settings
            otr_flags = self.plugin.get_flags(self.account)
            self.gw('otr_default_checkbutton').set_active(1)
            for w in self.gw('otr_settings_vbox').get_children():
                w.set_sensitive(False)

        self.gw('otr_policy_allow_v2_checkbutton').set_active(
                otr_flags['ALLOW_V2'])
        self.gw('otr_policy_require_checkbutton').set_active(
                otr_flags['REQUIRE_ENCRYPTION'])
        self.gw('otr_policy_send_tag_checkbutton').set_active(
                otr_flags['SEND_TAG'])
        self.gw('otr_policy_start_on_tag_checkbutton').set_active(
                otr_flags['WHITESPACE_START_AKE'])

        self.child.show_all()

    def on_response(self, dlg, response, *args):
        if response != gtk.RESPONSE_ACCEPT:
            return


        # -1 when nothing is selected
        # (ie. the connection is not encrypted)
        trust_state = self.gw('verified_combobox').get_active()
        if trust_state == 1 and not self.ctx.getTrust(self.fpr):
            self.ctx.setTrust(self.fpr, 'verified')
            self.ctx.user.saveTrusts()
            self.plugin.update_context_list()
        elif trust_state == 0:
            self.ctx.setTrust(self.fpr, '')
            self.ctx.user.saveTrusts()
            self.plugin.update_context_list()

        self.plugin.update_otr(self.ctx.peer, self.ctx.user.accountname, True)

        if self.gw('otr_default_checkbutton').get_active():
            # default is enabled, so remove any user-specific
            # settings if available
            self.plugin.set_flags(None, self.account, self.jid)
        else:
            # build the flags using the checkboxes
            flags = {}
            flags['ALLOW_V2'] = \
                    self.gw('otr_policy_allow_v2_checkbutton').get_active()
            flags['REQUIRE_ENCRYPTION'] = \
                    self.gw('otr_policy_require_checkbutton').get_active()
            flags['SEND_TAG'] = \
                    self.gw('otr_policy_send_tag_checkbutton').get_active()
            flags['WHITESPACE_START_AKE'] = \
                    self.gw('otr_policy_start_on_tag_checkbutton').get_active()

            self.plugin.set_flags(flags, self.account, self.jid)

    def _otr_default_checkbutton_toggled(self, widget):
        for w in self.gw('otr_settings_vbox').get_children():
            w.set_sensitive(not widget.get_active())

def get_otr_submenu(plugin, control):
    GTK_BUILDER_FILE_PATH = \
            plugin.local_file_path('contact_otr_window.ui')
    xml = gtk.Builder()
    xml.set_translation_domain('gajim_plugins')
    xml.add_from_file(GTK_BUILDER_FILE_PATH)

    otr_submenu = xml.get_object('otr_submenu')
    otr_settings_menuitem, smp_otr_menuitem, start_otr_menuitem, \
            end_otr_menuitem = otr_submenu.get_submenu().get_children()

    otr_submenu.set_sensitive(True)
    otr_settings_menuitem.connect('activate', plugin.menu_settings_cb, control)
    start_otr_menuitem.connect('activate', plugin.menu_start_cb, control)
    end_otr_menuitem.connect('activate', plugin.menu_end_cb, control)
    smp_otr_menuitem.connect('activate', plugin.menu_smp_cb, control)

    enc, _, fin = plugin.get_otr_status(control.account, control.contact)
    # can end only when not in PLAINTEXT
    end_otr_menuitem.set_sensitive(enc)
    # can SMP only when ENCRYPTED
    smp_otr_menuitem.set_sensitive(enc and not fin)
    return otr_submenu
