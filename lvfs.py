#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import hashlib
import math
import calendar
import datetime
import ConfigParser
from StringIO import StringIO

from flask import Blueprint, session, request, flash, url_for, redirect, \
     render_template
from flask.ext.login import login_required, login_user, logout_user
from flask import current_app as app

import cabarchive
import appstream
from affidavit import NoKeyError
from db import LvfsDatabase, CursorError
from db_clients import LvfsDatabaseClients, LvfsDownloadKind
from db_eventlog import LvfsDatabaseEventlog
from db_firmware import LvfsDatabaseFirmware, LvfsFirmware, LvfsFirmwareMd
from db_users import LvfsDatabaseUsers, _password_hash
from inf_parser import InfParser
from util import _qa_hash, _upload_to_cdn, create_affidavit
from metadata import metadata_update_qa_group, metadata_update_targets, metadata_update_pulp

def _password_check(value):
    """ Check the password for suitability """
    success = True
    if len(value) < 8:
        success = False
        flash('The password is too short, the minimum is 8 characters')
    if len(value) > 40:
        success = False
        flash('The password is too long, the maximum is 40 characters')
    if value.lower() == value:
        success = False
        flash('The password requires at least one uppercase character')
    if value.isalnum():
        success = False
        flash('The password requires at least one non-alphanumeric character')
    return success

def _email_check(value):
    """ Do a quick and dirty check on the email address """
    if len(value) < 5 or value.find('@') == -1 or value.find('.') == -1:
        flash('Invalid email address')
        return False
    return True

def _get_chart_labels_months():
    """ Gets the chart labels """
    now = datetime.date.today()
    labels = []
    offset = 0
    for i in range(0, 12):
        if now.month - i == 0:
            offset = 1
        labels.append(calendar.month_name[now.month - i - offset])
    return labels

def _get_chart_labels_days():
    """ Gets the chart labels """
    now = datetime.date.today()
    labels = []
    for i in range(0, 30):
        then = now - datetime.timedelta(i)
        labels.append("%02i-%02i-%02i" % (then.year, then.month, then.day))
    return labels

def _get_chart_labels_hours():
    """ Gets the chart labels """
    labels = []
    for i in range(0, 24):
        labels.append("%02i" % i)
    return labels

def _to_javascript_array(arr):
    tmp = '['
    for a in arr:
        if type(a) == unicode:
            tmp += '"' + a + '",'
        elif type(a) == long:
            tmp += str(a) + ','
        else:
            tmp += '"' + str(a) + '",'
    if len(tmp) > 1:
        tmp = tmp[:-1]
    tmp += ']'
    return tmp

def _get_client_address():
    """ Gets user IP address """
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def _event_log(msg, is_important=False):
    """ Adds an item to the event log """
    username = None
    qa_group = None
    if 'username' in session:
        username = session['username']
    if not username:
        username = 'anonymous'
    if 'qa_group' in session:
        qa_group = session['qa_group']
    if not qa_group:
        qa_group = 'admin'
    db = LvfsDatabase(os.environ)
    db_eventlog = LvfsDatabaseEventlog(db)
    db_eventlog.add(msg, username, qa_group,
                    _get_client_address(), is_important)

def _check_session():
    if 'username' not in session:
        return False
    if 'qa_group' not in session:
        return False
    if 'qa_capability' not in session:
        return False
    if 'is_locked' not in session:
        return False
    return True

################################################################################

lvfs = Blueprint('lvfs', __name__, url_prefix='/lvfs', template_folder='templates/lvfs')

@lvfs.context_processor
def utility_processor():

    def format_truncate(tmp, length):
        if len(tmp) <= length:
            return tmp
        return tmp[:length] + u'…'

    def format_timestamp(tmp):
        if not tmp:
            return 'n/a'
        return datetime.datetime.fromtimestamp(tmp).strftime('%Y-%m-%d %H:%M:%S')

    def format_size(num, suffix='B'):
        if type(num) not in (int, long):
            return "???%s???" % num
        for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
            if abs(num) < 1024.0:
                return "%3.1f%s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f%s%s" % (num, 'Yi', suffix)

    def format_qa_hash(tmp):
        return _qa_hash(tmp)

    return dict(format_size=format_size,
                format_truncate=format_truncate,
                format_qa_hash=format_qa_hash,
                format_timestamp=format_timestamp)

@lvfs.errorhandler(401)
def error_permission_denied(msg=None):
    """ Error handler: Permission Denied """
    _event_log("Permission denied: %s" % msg, is_important=True)
    flash("Permission denied: %s" % msg)
    return render_template('error.html'), 401

def error_internal(msg=None, errcode=402):
    """ Error handler: Internal """
    _event_log("Internal error: %s" % msg, is_important=True)
    flash("Internal error: %s" % msg)
    return render_template('error.html'), errcode

@lvfs.route('/')
def index():
    """
    The main page that shows existing firmware and also allows the
    user to add new firmware.
    """
    if 'username' not in session:
        return redirect(url_for('.login'))
    try:
        db = LvfsDatabase(os.environ)
        db_users = LvfsDatabaseUsers(db)
        item = db_users.get_item(session['username'])
    except CursorError as e:
        return error_internal(str(e))
    return render_template('index.html', vendor_ids=item.vendor_ids)

@lvfs.route('/newaccount')
def new_account():
    """ New account page for prospective vendors """
    return render_template('new-account.html')

@lvfs.route('/metadata')
@login_required
def metadata():
    """
    Show all metadata available to this user.
    """

    # show all embargo metadata URLs when admin user
    qa_groups = []
    if session['qa_group'] == 'admin':
        db = LvfsDatabase(os.environ)
        db_users = LvfsDatabaseUsers(db)
        try:
            qa_groups = db_users.get_qa_groups()
        except CursorError as e:
            return error_internal(str(e))
    else:
        qa_groups.append(session['qa_group'])
    return render_template('metadata.html',
                           qa_group=session['qa_group'],
                           qa_groups=qa_groups)

@lvfs.route('/devicelist')
def device_list():
    # add devices in stable or testing
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        items = db_firmware.get_items()
    except CursorError as e:
        return error_internal(str(e))

    # get a sorted list of vendors
    vendors = []
    for item in items:
        if item.target not in ['stable', 'testing']:
            continue
        vendor = item.mds[0].developer_name
        if vendor in vendors:
            continue
        vendors.append(vendor)

    seen_ids = {}
    mds_by_vendor = {}
    for vendor in sorted(vendors):
        for item in items:
            if item.target not in ['stable', 'testing']:
                continue
            for md in item.mds:

                # only show correct vendor
                if vendor != md.developer_name:
                    continue

                # only show the newest version
                if md.cid in seen_ids:
                    continue
                seen_ids[md.cid] = 1

                # add
                if not vendor in mds_by_vendor:
                    mds_by_vendor[vendor] = []
                mds_by_vendor[vendor].append(md)

    # ensure list is sorted
    for vendor in mds_by_vendor:
        mds_by_vendor[vendor].sort(key=lambda obj: obj.name)

    return render_template('devicelist.html',
                           vendors=sorted(vendors),
                           mds_by_vendor=mds_by_vendor)

@lvfs.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """ Upload a .cab file to the LVFS service """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.index'))

    # not correct parameters
    if not 'target' in request.form:
        return error_internal('No target')
    if not 'file' in request.files:
        return error_internal('No file')

    # can the user upload directly to stable
    if request.form['target'] in ['stable', 'testing']:
        if not session['qa_capability']:
            return error_permission_denied('Unable to upload to this target as not QA user')

    # check size < 50Mb
    fileitem = request.files['file']
    if not fileitem:
        return error_internal('No file object')
    data = fileitem.read()
    if len(data) > 50000000:
        return error_internal('File too large, limit is 50Mb', 413)
    if len(data) == 0:
        return error_internal('File has no content')
    if len(data) < 1024:
        return error_internal('File too small, mimimum is 1k')

    # check the file does not already exist
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    fwid = hashlib.sha1(data).hexdigest()
    try:
        item = db_firmware.get_item(fwid)
    except CursorError as e:
        return error_internal(str(e))
    if item:
        return error_internal("A firmware file with hash %s already exists" % fwid, 422)

    # parse the file
    arc = cabarchive.CabArchive()
    try:
        cabextract_cmd = app.config['CABEXTRACT_CMD']
        if os.path.exists(cabextract_cmd):
            arc.set_decompressor(cabextract_cmd)
        arc.parse(data)
    except cabarchive.CorruptionError as e:
        return error_internal('Invalid file type: %s' % str(e), 415)
    except cabarchive.NotSupportedError as e:
        return error_internal('The file is unsupported: %s' % str(e), 415)

    # check .inf exists
    fw_version_inf = None
    fw_version_display_inf = None
    cf = arc.find_file("*.inf")
    if cf:
        if cf.contents.find('FIXME') != -1:
            return error_internal("The inf file was not complete; "
                                  "Any FIXME text must be replaced with the correct values.")

        # check .inf file is valid
        cfg = InfParser()
        cfg.read_data(cf.contents)
        try:
            tmp = cfg.get('Version', 'Class')
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError) as e:
            return error_internal('The inf file Version:Class was missing')
        if tmp != 'Firmware':
            return error_internal('The inf file Version:Class was invalid')
        try:
            tmp = cfg.get('Version', 'ClassGuid')
        except ConfigParser.NoOptionError as e:
            return error_internal('The inf file Version:ClassGuid was missing')
        if tmp != '{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}':
            return error_internal('The inf file Version:ClassGuid was invalid')
        try:
            tmp = cfg.get('Version', 'DriverVer')
            fw_version_display_inf = tmp.split(',')
            if len(fw_version_display_inf) != 2:
                return error_internal('The inf file Version:DriverVer was invalid')
        except ConfigParser.NoOptionError as e:
            pass

        # this is optional, but if supplied must match the version in the XML
        # -- also note this will not work with multi-firmware .cab files
        try:
            fw_version_inf = cfg.get('Firmware_AddReg', 'HKR->FirmwareVersion')
            if fw_version_inf.startswith('0x'):
                fw_version_inf = str(int(fw_version_inf[2:], 16))
            if fw_version_inf == '0':
                fw_version_inf = None
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError) as e:
            pass

    # check metainfo exists
    cfs = arc.find_files("*.metainfo.xml")
    if len(cfs) == 0:
        return error_internal('The firmware file had no .metadata.xml files')

    # parse each MetaInfo file
    apps = []
    for cf in cfs:
        component = appstream.Component()
        try:
            component.parse(str(cf.contents))
            component.validate()
        except appstream.ParseError as e:
            return error_internal('The metadata %s could not be parsed: %s' % (cf, str(e)))
        except appstream.ValidationError as e:
            return error_internal('The metadata %s file did not validate: %s' % (cf, str(e)))

        # get the metadata ID
        component.custom['metainfo_id'] = hashlib.sha1(cf.contents).hexdigest()

        # check the file does not have any missing request.form
        if cf.contents.find('FIXME') != -1:
            return error_internal("The metadata file was not complete; "
                                  "Any FIXME text must be replaced with the correct values.")

        # check the firmware provides something
        if len(component.provides) == 0:
            return error_internal("The metadata file did not provide any GUID.")
        if len(component.releases) == 0:
            return error_internal("The metadata file did not provide any releases.")

        # check the inf file matches up with the .xml file
        if fw_version_inf and fw_version_inf != component.releases[0].version:
            return error_internal("The inf Firmware_AddReg[HKR->FirmwareVersion] "
                                  "'%s' did not match the metainfo.xml value '%s'."
                                  % (fw_version_inf, component.releases[0].version))

        # check the guid and version does not already exist
        try:
            items = db_firmware.get_items()
        except CursorError as e:
            return error_internal(str(e))
        for item in items:
            for md in item.mds:
                for guid in md.guids:
                    if guid == component.provides[0].value and md.version == component.releases[0].version:
                        return error_internal("A firmware file for this version already exists", 422)

        # check if the file dropped a GUID previously supported
        new_guids = []
        for prov in component.provides:
            new_guids.append(prov.value)
        for item in items:
            for md in item.mds:
                if md.cid != component.id:
                    continue
                for old_guid in md.guids:
                    if not old_guid in new_guids:
                        return error_internal("Firmware %s dropped a GUID previously supported %s" % (md.cid, old_guid), 422)

        # check the file didn't try to add it's own <require> on vendor-id
        # to work around the vendor-id security checks in fwupd
        req = component.get_require_by_kind('firmware', 'vendor-id')
        if req:
            return error_internal("Firmware cannot specify vendor-id", 422)

        # add to array
        apps.append(component)

    # only save if we passed all tests
    basename = os.path.basename(fileitem.filename)
    new_filename = fwid + '-' + basename

    # add these after parsing in case multiple components use the same file
    asc_files = {}

    # fix up the checksums and add the detached signature
    for component in apps:

        # ensure there's always a container checksum
        release = component.releases[0]
        csum = release.get_checksum_by_target('content')
        if not csum:
            csum = appstream.Checksum()
            csum.target = 'content'
            csum.filename = 'firmware.bin'
            component.releases[0].add_checksum(csum)

        # get the contents checksum
        fw_data = arc.find_file(csum.filename)
        if not fw_data:
            return error_internal('No %s found in the archive' % csum.filename)
        csum.kind = 'sha1'
        csum.value = hashlib.sha1(fw_data.contents).hexdigest()

        # set the sizes
        release.size_installed = len(fw_data.contents)
        release.size_download = len(data)

        # add the detached signature if not already signed
        sig_data = arc.find_file(csum.filename + ".asc")
        if not sig_data:
            if csum.filename not in asc_files:
                try:
                    affidavit = create_affidavit()
                except NoKeyError as e:
                    return error_internal('Failed to sign archive: ' + str(e))
                cff = cabarchive.CabFile(fw_data.filename + '.asc',
                                         affidavit.create(fw_data.contents))
                asc_files[csum.filename] = cff
        else:
            # check this file is signed by something we trust
            try:
                affidavit = create_affidavit()
                affidavit.verify(fw_data.contents)
            except NoKeyError as e:
                return error_internal('Failed to verify archive: ' + str(e))

    # add all the .asc files to the archive
    for key in asc_files:
        arc.add_file(asc_files[key])

    # export the new archive and get the checksum
    cab_data = arc.save(compressed=True)
    checksum_container = hashlib.sha1(cab_data).hexdigest()

    # dump to a file
    download_dir = app.config['DOWNLOAD_DIR']
    if not os.path.exists(download_dir):
        os.mkdir(download_dir)
    fn = os.path.join(download_dir, new_filename)
    open(fn, 'wb').write(cab_data)

    # dump to the CDN
    _upload_to_cdn(new_filename, StringIO(cab_data))

    # create parent firmware object
    target = request.form['target']
    fwobj = LvfsFirmware()
    fwobj.qa_group = session['qa_group']
    fwobj.addr = _get_client_address()
    fwobj.filename = new_filename
    fwobj.fwid = fwid
    fwobj.target = target
    if fw_version_display_inf:
        fwobj.version_display = fw_version_display_inf[1]

    # create child metadata object for the component
    for component in apps:
        md = LvfsFirmwareMd()
        md.fwid = fwid
        md.metainfo_id = component.custom['metainfo_id']
        md.cid = component.id
        md.name = component.name
        md.summary = component.summary
        md.developer_name = component.developer_name
        md.metadata_license = component.metadata_license
        md.project_license = component.project_license
        md.url_homepage = component.urls['homepage']
        md.description = component.description
        md.checksum_container = checksum_container

        # from the provide
        for prov in component.provides:
            md.guids.append(prov.value)

        # from the release
        rel = component.releases[0]
        md.version = rel.version
        md.release_description = rel.description
        md.release_timestamp = rel.timestamp
        md.release_installed_size = rel.size_installed
        md.release_download_size = rel.size_download
        md.release_urgency = rel.urgency

        # from the first screenshot
        if len(component.screenshots) > 0:
            ss = component.screenshots[0]
            if ss.caption:
                md.screenshot_caption = ss.caption
            if len(ss.images) > 0:
                im = ss.images[0]
                if im.url:
                    md.screenshot_url = im.url

        # from the content checksum
        csum = component.releases[0].get_checksum_by_target('content')
        md.checksum_contents = csum.value
        md.filename_contents = csum.filename

        fwobj.mds.append(md)

    # add to database
    try:
        db_firmware.add(fwobj)
    except CursorError as e:
        return error_internal(str(e))
    # set correct response code
    _event_log("Uploaded file %s to %s" % (new_filename, target))

    # ensure up to date
    try:
        if target != 'private':
            metadata_update_qa_group(fwobj.qa_group)
        if target == 'stable':
            metadata_update_targets(['stable', 'testing'])
        elif target == 'testing':
            metadata_update_targets(['testing'])

    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))
    except CursorError as e:
        return error_internal('Failed to generate metadata: ' + str(e))

    return redirect(url_for('.firmware_id', fwid=fwid))

@lvfs.route('/dbmigrate')
@login_required
def dbmigrate():
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    db_firmware.migrate()
    return redirect(url_for('.index'))

@lvfs.route('/device')
@login_required
def device():
    """
    Show all devices -- probably only useful for the admin user.
    """

    # security check
    if session['username'] != 'admin':
        return error_permission_denied('Unable to view devices')

    # get all firmware
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        items = db_firmware.get_items()
    except CursorError as e:
        return error_internal(str(e))

    # get all the guids we can target
    devices = []
    seen_guid = {}
    for item in items:
        for md in item.mds:
            if md.guids[0] in seen_guid:
                continue
            seen_guid[md.guids[0]] = 1
            devices.append(md.guids[0])

    return render_template('devices.html', devices=devices)

@lvfs.route('/device/<guid>')
def device_guid(guid):
    """
    Show information for one device, which can be seen without a valid login
    """

    # get all firmware
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        items = db_firmware.get_items()
    except CursorError as e:
        return error_internal(str(e))

    # get all the guids we can target
    firmware_items = []
    for item in items:
        for md in item.mds:
            if md.guids[0] != guid:
                continue
            firmware_items.append(item)
            break

    return render_template('device.html', items=firmware_items)

@lvfs.route('/firmware')
def firmware(show_all=False):
    """
    Show all previsouly uploaded firmware for this user.
    """

    # get all firmware
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        items = db_firmware.get_items()
    except CursorError as e:
        return error_internal(str(e))

    session_qa_group = None
    if 'qa_group' in session:
        session_qa_group = session['qa_group']
    session_username = None
    if 'username' in session:
        session_username = session['username']

    # group by the firmware name
    names = {}
    for item in items:
        # admin can see everything
        if session_username != 'admin':
            if item.qa_group != session_qa_group:
                continue
        name = item.mds[0].developer_name + ' ' + item.mds[0].name
        if not name in names:
            names[name] = []
        names[name].append(item)

    # only show one version in each state
    for name in sorted(names):
        targets_seen = {}
        for item in names[name]:
            key = item.target + item.mds[0].cid
            if key in targets_seen:
                item.is_newest_in_state = False
            else:
                item.is_newest_in_state = True
                targets_seen[key] = item

    return render_template('firmware.html',
                           fw_by_name=names,
                           names_sorted=sorted(names),
                           qa_group=session_qa_group,
                           show_all=show_all)

@lvfs.route('/firmware_all')
def firmware_all():
    return firmware(True)

@lvfs.route('/firmware/<fwid>/delete')
def firmware_delete(fwid):
    """ Confirms deletion of firmware """
    return render_template('firmware-delete.html', fwid=fwid), 406

@lvfs.route('/firmware/<fwid>/modify', methods=['GET', 'POST'])
@login_required
def firmware_modify(fwid):
    """ Modifies the update urgency and release notes for the update """

    if request.method != 'POST':
        return redirect(url_for('.firmware'))

    # find firmware
    try:
        db = LvfsDatabase(os.environ)
        db_firmware = LvfsDatabaseFirmware(db)
        fwobj = db_firmware.get_item(fwid)
    except CursorError as e:
        return error_internal(str(e))
    if not fwobj:
        return error_internal("No firmware %s" % fwid)

    # set new metadata values
    for md in fwobj.mds:
        if 'urgency' in request.form:
            md.release_urgency = request.form['urgency']
        if 'description' in request.form:
            txt = request.form['description']
            if txt.find('<p>') == -1:
                txt = appstream.utils.import_description(txt)
            try:
                appstream.utils.validate_description(txt)
            except appstream.ParseError as e:
                return error_internal("Failed to parse %s: %s" % (txt, str(e)))
            md.release_description = txt

    # modify
    try:
        db_firmware.update(fwobj)
    except CursorError as e:
        return error_internal(str(e))

    # log
    _event_log('Changed update description on %s' % fwid)

    return redirect(url_for('.firmware_id', fwid=fwid))

@lvfs.route('/firmware/<fwid>/delete_force')
@login_required
def firmware_delete_force(fwid):
    """ Delete a firmware entry and also delete the file from disk """

    # check firmware exists in database
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    try:
        item = db_firmware.get_item(fwid)
    except CursorError as e:
        return error_internal(str(e))
    if not item:
        return error_internal("No firmware file with hash %s exists" % fwid)
    if session['username'] != 'admin' and item.qa_group != session['qa_group']:
        return error_permission_denied("No QA access to %s" % fwid)

    # only QA users can delete once the firmware has gone stable
    if not session['qa_capability'] and item.target == 'stable':
        return error_permission_denied('Unable to delete stable firmware as not QA')

    # delete id from database
    try:
        db_firmware.remove(fwid)
    except CursorError as e:
        return error_internal(str(e))

    # delete file
    path = os.path.join(app.config['DOWNLOAD_DIR'], item.filename)
    if os.path.exists(path):
        os.remove(path)

    # update everything
    try:
        metadata_update_qa_group(item.qa_group)
        if item.target == 'stable':
            metadata_update_targets(targets=['stable', 'testing'])
        elif item.target == 'testing':
            metadata_update_targets(targets=['testing'])
    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))
    except CursorError as e:
        return error_internal('Failed to generate metadata: ' + str(e))

    _event_log("Deleted firmware %s" % fwid)
    return redirect(url_for('.firmware'))

@lvfs.route('/firmware/<fwid>/promote/<target>')
@login_required
def firmware_promote(fwid, target):
    """
    Promote or demote a firmware file from one target to another,
    for example from testing to stable, or stable to testing.
     """

    # check is QA
    if not session['qa_capability']:
        return error_permission_denied('Unable to promote as not QA')

    # check valid
    if target not in ['stable', 'testing', 'private', 'embargo']:
        return error_internal("Target %s invalid" % target)

    # check firmware exists in database
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    try:
        item = db_firmware.get_item(fwid)
    except CursorError as e:
        return error_internal(str(e))
    if session['username'] != 'admin' and item.qa_group != session['qa_group']:
        return error_permission_denied("No QA access to %s" % fwid)
    try:
        db_firmware.set_target(fwid, target)
    except CursorError as e:
        return error_internal(str(e))
    # set correct response code
    _event_log("Moved firmware %s to %s" % (fwid, target))

    # update everything
    try:
        metadata_update_qa_group(item.qa_group)
        if target == 'stable':
            metadata_update_targets(['stable', 'testing'])
        elif target == 'testing':
            metadata_update_targets(['testing'])
    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))
    except CursorError as e:
        return error_internal('Failed to generate metadata: ' + str(e))
    return redirect(url_for('.firmware_id', fwid=fwid))

@lvfs.route('/firmware/<fwid>')
@login_required
def firmware_id(fwid):
    """ Show firmware information """

    # get details about the firmware
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    try:
        item = db_firmware.get_item(fwid)
    except CursorError as e:
        return error_internal(str(e))
    if not item:
        return error_internal('No firmware matched!')

    # we can only view our own firmware, unless admin
    qa_group = item.qa_group
    if qa_group != session['qa_group'] and session['username'] != 'admin':
        return error_permission_denied('Unable to view other vendor firmware')
    if not qa_group:
        embargo_url = '/downloads/firmware.xml.gz'
        qa_group = 'None'
    else:
        embargo_url = '/downloads/firmware-%s.xml.gz' % _qa_hash(qa_group)

    db = LvfsDatabase(os.environ)
    db_clients = LvfsDatabaseClients(db)
    cnt_fn = db_clients.get_firmware_count_filename(item.filename)
    data_fw = db_clients.get_stats_for_fn(12, 30, item.filename)
    return render_template('firmware-details.html',
                           fw=item,
                           qa_capability=session['qa_capability'],
                           orig_filename='-'.join(item.filename.split('-')[1:]),
                           embargo_url=embargo_url,
                           qa_group=qa_group,
                           cnt_fn=cnt_fn,
                           fwid=fwid,
                           graph_labels=_get_chart_labels_months()[::-1],
                           graph_data=data_fw[::-1])

@lvfs.route('/analytics')
@login_required
def analytics():
    """ A analytics screen to show information about users """

    # security check
    if session['username'] != 'admin':
        return error_permission_denied('Unable to view analytics')
    db = LvfsDatabase(os.environ)
    db_clients = LvfsDatabaseClients(db)
    labels_days = _get_chart_labels_days()[::-1]
    data_days = db_clients.get_stats_for_month(LvfsDownloadKind.FIRMWARE)[::-1]
    labels_months = _get_chart_labels_months()[::-1]
    data_months = db_clients.get_stats_for_year(LvfsDownloadKind.FIRMWARE)[::-1]
    labels_user_agent, data_user_agent = db_clients.get_user_agent_stats()
    return render_template('analytics.html',
                           labels_days=labels_days,
                           data_days=data_days,
                           labels_months=labels_months,
                           data_months=data_months,
                           labels_user_agent=labels_user_agent,
                           data_user_agent=data_user_agent)

@lvfs.route('/login', methods=['GET', 'POST'])
def login():
    """ A login screen to allow access to the LVFS main page """
    if request.method != 'POST':
        return render_template('login.html')

    # auth check
    user = None
    password = _password_hash(request.form['password'])
    try:
        db = LvfsDatabase(os.environ)
        db_users = LvfsDatabaseUsers(db)
        user = db_users.get_item(request.form['username'],
                                 password)
    except CursorError as e:
        return error_internal(str(e))
    if not user:
        # log failure
        _event_log('Failed login attempt for %s' % request.form['username'])
        flash('Incorrect username or password')
        return render_template('login.html')
    if not user.is_enabled:
        # log failure
        _event_log('Failed login attempt for %s (user disabled)' % request.form['username'])
        flash('User account is disabled')
        return render_template('login.html')

    # this is signed, not encrypted
    session['username'] = user.username
    session['qa_capability'] = user.is_qa
    session['qa_group'] = user.qa_group
    session['is_locked'] = user.is_locked
    login_user(user, remember=False)

    # log success
    _event_log('Logged on')
    return redirect(url_for('.index'))

@lvfs.route('/logout')
def logout():
    # remove the username from the session
    session.pop('username', None)
    logout_user()
    return redirect(url_for('.index'))

@lvfs.route('/eventlog')
@lvfs.route('/eventlog/<start>')
@lvfs.route('/eventlog/<start>/<length>')
@login_required
def eventlog(start=0, length=20):
    """
    Show an event log of user actions.
    """
    # security check
    if not session['qa_capability']:
        return error_permission_denied('Unable to show event log for non-QA user')

    # get the page selection correct
    db = LvfsDatabase(os.environ)
    db_eventlog = LvfsDatabaseEventlog(db)
    if session['username'] == 'admin':
        eventlog_len = db_eventlog.size()
    else:
        eventlog_len = db_eventlog.size_for_qa_group(session['qa_group'])
    nr_pages = int(math.ceil(eventlog_len / float(length)))

    # table contents
    try:
        if session['username'] == 'admin':
            items = db_eventlog.get_items(int(start), int(length))
        else:
            items = db_eventlog.get_items_for_qa_group(session['qa_group'], int(start), int(length))
    except CursorError as e:
        return error_internal(str(e))
    if len(items) == 0:
        return error_internal('No event log available!')

    # limit this to keep the UI sane
    if nr_pages > 20:
        nr_pages = 20

    html = ''
    for i in range(nr_pages):
        if int(start) == i * int(length):
            html += '%i ' % (i + 1)
        else:
            html += '<a href="/lvfs/eventlog/%i/%s">%i</a> ' % (i * int(length), int(length), i + 1)
    return render_template('eventlog.html', events=items, pagination_footer=html)

def _update_metadata_from_fn(fwobj, fn):
    """
    Re-parses the .cab file and updates the database version.
    """

    # load cab file
    arc = cabarchive.CabArchive()
    try:
        cabextract_cmd = app.config['CABEXTRACT_CMD']
        if os.path.exists(cabextract_cmd):
            arc.set_decompressor(cabextract_cmd)
        arc.parse_file(fn)
    except cabarchive.CorruptionError as e:
        return error_internal('Invalid file type: %s' % str(e))

    # parse the MetaInfo file
    cf = arc.find_file("*.metainfo.xml")
    if not cf:
        return error_internal('The firmware file had no valid metadata')
    component = appstream.Component()
    try:
        component.parse(str(cf.contents))
    except appstream.ParseError as e:
        return error_internal('The metadata could not be parsed: ' + str(e))

    # parse the inf file
    cf = arc.find_file("*.inf")
    if not cf:
        return error_internal('The firmware file had no valid inf file')
    cfg = InfParser()
    cfg.read_data(cf.contents)
    try:
        tmp = cfg.get('Version', 'DriverVer')
        driver_ver = tmp.split(',')
        if len(driver_ver) != 2:
            return error_internal('The inf file Version:DriverVer was invalid')
    except ConfigParser.NoOptionError as e:
        driver_ver = None

    # get the contents
    fw_data = arc.find_file('*.bin')
    if not fw_data:
        fw_data = arc.find_file('*.rom')
    if not fw_data:
        fw_data = arc.find_file('*.cap')
    if not fw_data:
        return error_internal('No firmware found in the archive')

    # update sizes
    fwobj.mds[0].release_installed_size = len(fw_data.contents)
    fwobj.mds[0].release_download_size = os.path.getsize(fn)

    # update the descriptions
    fwobj.mds[0].release_description = component.releases[0].description
    fwobj.mds[0].description = component.description
    if driver_ver:
        fwobj.version_display = driver_ver[1]
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    db_firmware.update(fwobj)
    return None

@lvfs.route('/user/<username>/modify', methods=['GET', 'POST'])
@login_required
def user_modify(username):
    """ Change details about the current user """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.profile'))

    # security check
    if session['username'] != username:
        return error_permission_denied('Unable to modify a different user')
    if session['is_locked']:
        return error_permission_denied('Unable to change user as account locked')

    # check we got enough data
    if not 'password_new' in request.form:
        return error_permission_denied('Unable to change user as no data')
    if not 'password_old' in request.form:
        return error_permission_denied('Unable to change user as no data')
    if not 'name' in request.form:
        return error_permission_denied('Unable to change user as no data')
    if not 'email' in request.form:
        return error_permission_denied('Unable to change user as no data')
    db = LvfsDatabase(os.environ)
    db_users = LvfsDatabaseUsers(db)
    try:
        auth = db_users.verify(session['username'], request.form['password_old'])
    except CursorError as e:
        return error_internal(str(e))
    if not auth:
        return error_internal('Incorrect existing password')

    # check password
    password = request.form['password_new']
    if not _password_check(password):
        return redirect(url_for('.profile')), 400

    # check email
    email = request.form['email']
    if not _email_check(email):
        return redirect(url_for('.profile'))

    # check pubkey
    pubkey = ''
    if 'pubkey' in request.form:
        pubkey = request.form['pubkey']
        if pubkey:
            if len(pubkey) > 0:
                if not pubkey.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"):
                    flash('Invalid GPG public key')
                    return redirect(url_for('.profile')), 400

    # verify name
    name = request.form['name']
    if len(name) < 3:
        flash('Name invalid')
        return redirect(url_for('.profile')), 400
    try:
        db_users.update(session['username'], password, name, email, pubkey)
    except CursorError as e:
        return error_internal(str(e))
    #session['password'] = _password_hash(password)
    _event_log('Changed password')
    flash('Updated profile')
    return redirect(url_for('.profile'))

@lvfs.route('/user/<username>/modify_by_admin', methods=['POST'])
@login_required
def user_modify_by_admin(username):
    """ Change details about the any user """

    # security check
    if session['username'] != 'admin':
        return error_permission_denied('Unable to modify user as non-admin')

    # set each thing in turn
    for key in ['qa_group',
                'display_name',
                'email',
                'vendor_ids',
                'password',
                'is_enabled',
                'is_qa',
                'is_locked',
                'pubkey']:
        # unchecked checkbuttons are not included in the form data
        if key in request.form:
            tmp = request.form[key]
        else:
            tmp = '0'
        try:
            db = LvfsDatabase(os.environ)
            db_users = LvfsDatabaseUsers(db)
            # don't set the optional password
            if key == 'password' and len(tmp) == 0:
                continue
            db_users.set_property(username, key, tmp)
        except CursorError as e:
            return error_internal(str(e))
    _event_log('Changed user %s properties' % username)
    flash('Updated profile')
    return redirect(url_for('.user_admin', user_name=username))

@lvfs.route('/user/add', methods=['GET', 'POST'])
@login_required
def useradd():
    """ Add a user [ADMIN ONLY] """

    # only accept form data
    if request.method != 'POST':
        return redirect(url_for('.profile'))

    # security check
    if session['username'] != 'admin':
        return error_permission_denied('Unable to add user as non-admin')

    db = LvfsDatabase(os.environ)
    db_users = LvfsDatabaseUsers(db)
    if not 'password_new' in request.form:
        return error_permission_denied('Unable to add user an no data')
    if not 'username_new' in request.form:
        return error_permission_denied('Unable to add user an no data')
    if not 'qa_group' in request.form:
        return error_permission_denied('Unable to add user an no data')
    if not 'name' in request.form:
        return error_permission_denied('Unable to add user an no data')
    if not 'email' in request.form:
        return error_permission_denied('Unable to add user an no data')
    try:
        auth = db_users.is_enabled(request.form['username_new'])
    except CursorError as e:
        return error_internal(str(e))
    if auth:
        return error_internal('Already a entry with that username', 422)

    # verify password
    password = request.form['password_new']
    if not _password_check(password):
        return redirect(url_for('.userlist')), 302

    # verify email
    email = request.form['email']
    if not _email_check(email):
        return redirect(url_for('.userlist')), 302

    # verify qa_group
    qa_group = request.form['qa_group']
    if len(qa_group) < 3:
        flash('QA group invalid')
        return redirect(url_for('.userlist')), 302

    # verify name
    name = request.form['name']
    if len(name) < 3:
        flash('Name invalid')
        return redirect(url_for('.userlist')), 302

    # verify username
    username_new = request.form['username_new']
    if len(username_new) < 3:
        flash('Username invalid')
        return redirect(url_for('.userlist')), 302
    try:
        db_users.add(username_new, password, name, email, qa_group)
    except CursorError as e:
        return error_internal(str(e))
    _event_log("Created user %s" % username_new)
    flash('Added user')
    return redirect(url_for('.userlist')), 201

@lvfs.route('/user/<username>/delete')
@login_required
def user_delete(username):
    """ Delete a user """

    # security check
    if session['username'] != 'admin':
        return error_permission_denied('Unable to remove user as not admin')

    # check whether exists in database
    db = LvfsDatabase(os.environ)
    db_users = LvfsDatabaseUsers(db)
    try:
        exists = db_users.is_enabled(username)
    except CursorError as e:
        return error_internal(str(e))
    if not exists:
        flash("No entry with username %s" % username)
        return redirect(url_for('.userlist')), 400
    try:
        db_users.remove(username)
    except CursorError as e:
        return error_internal(str(e))
    _event_log("Deleted user %s" % username)
    flash('Deleted user')
    return redirect(url_for('.userlist')), 201

@lvfs.route('/schema_upgrade')
@login_required
def schema_upgrade():
    """ Upgrade the SQL schema """

    # security check
    if session['username'] != 'admin':
        return error_permission_denied('Unable to upgrade schema as not admin')
    try:
        db = LvfsDatabase(os.environ)
        db_users = LvfsDatabaseUsers(db)
        exists = db_users.upgrade_schema()
    except CursorError as e:
        return error_internal(str(e))
    flash('Upgraded database schema')
    return redirect(url_for('.index'))

@lvfs.route('/userlist')
@login_required
def userlist():
    """
    Show a list of all users
    """
    if session['username'] != 'admin':
        return error_permission_denied('Unable to show userlist for non-admin user')
    try:
        db = LvfsDatabase(os.environ)
        db_users = LvfsDatabaseUsers(db)
        items = db_users.get_items()
    except CursorError as e:
        return error_internal(str(e))
    return render_template('userlist.html', users=items)

@lvfs.route('/user/<user_name>/admin')
@login_required
def user_admin(user_name):
    """
    Shows an admin panel for a user
    """
    if session['username'] != 'admin':
        return error_permission_denied('Unable to modify user for non-admin user')
    try:
        db = LvfsDatabase(os.environ)
        db_users = LvfsDatabaseUsers(db)
        item = db_users.get_item(user_name)
    except CursorError as e:
        return error_internal(str(e))
    return render_template('useradmin.html', u=item)

@lvfs.route('/profile')
@login_required
def profile():
    """
    Allows the normal user to change details about the account,
    """

    # security check
    if session['is_locked']:
        return error_permission_denied('Unable to view profile as account locked')

    # auth check
    try:
        db = LvfsDatabase(os.environ)
        db_users = LvfsDatabaseUsers(db)
        item = db_users.get_item(session['username'])
    except CursorError as e:
        return error_internal(str(e))
    if not item:
        return error_internal('Invalid username query')

    # add defaults
    if not item.display_name:
        item.display_name = "Example Name"
    if not item.email:
        item.email = "info@example.com"
    return render_template('profile.html',
                           vendor_name=item.display_name,
                           contact_email=item.email,
                           pubkey=item.pubkey)

@lvfs.route('/metadata_rebuild')
@login_required
def metadata_rebuild():
    """
    Forces a rebuild of all metadata.
    """

    # security check
    if session['username'] != 'admin':
        return error_permission_denied('Only admin is allowed to force-rebuild metadata')

    # update metadata
    try:
        metadata_update_qa_group(None)
        metadata_update_targets(['stable', 'testing'])
        metadata_update_pulp()
    except NoKeyError as e:
        return error_internal('Failed to sign metadata: ' + str(e))
    except CursorError as e:
        return error_internal('Failed to generate metadata: ' + str(e))
    return redirect(url_for('.metadata'))
