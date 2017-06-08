#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import os
import hashlib

import appstream

from util import _qa_hash, _upload_to_cdn, create_affidavit
from db import LvfsDatabase
from db_firmware import LvfsDatabaseFirmware
from db_users import LvfsDatabaseUsers
from flask import current_app as app

def _generate_metadata_kind(filename, targets=None, qa_group=None, affidavit=None):
    """ Generates AppStream metadata of a specific kind """
    db = LvfsDatabase(os.environ)
    db_users = LvfsDatabaseUsers(db)
    db_firmware = LvfsDatabaseFirmware(db)
    items = db_firmware.get_items()
    store = appstream.Store('lvfs')
    for item in items:

        # filter
        if item.target == 'private':
            continue
        if targets and item.target not in targets:
            continue
        if qa_group and qa_group != item.qa_group:
            continue

        # add each component
        for md in item.mds:
            component = appstream.Component()
            component.id = md.cid
            component.kind = 'firmware'
            component.name = md.name
            component.summary = md.summary
            component.description = md.description
            if md.url_homepage:
                component.urls['homepage'] = md.url_homepage
            component.metadata_license = md.metadata_license
            component.project_license = md.project_license
            component.developer_name = md.developer_name

            # add provide
            for guid in md.guids:
                prov = appstream.Provide()
                prov.kind = 'firmware-flashed'
                prov.value = guid
                component.add_provide(prov)

            # add release
            if md.version:
                rel = appstream.Release()
                rel.version = md.version
                rel.description = md.release_description
                if md.release_timestamp:
                    rel.timestamp = md.release_timestamp
                rel.checksums = []
                rel.location = 'https://secure-lvfs.rhcloud.com/downloads/' + item.filename
                rel.size_installed = md.release_installed_size
                rel.size_download = md.release_download_size
                rel.urgency = md.release_urgency
                component.add_release(rel)

                # add container checksum
                if md.checksum_container:
                    csum = appstream.Checksum()
                    csum.target = 'container'
                    csum.value = md.checksum_container
                    csum.filename = item.filename
                    rel.add_checksum(csum)

                # add content checksum
                if md.checksum_contents:
                    csum = appstream.Checksum()
                    csum.target = 'content'
                    csum.value = md.checksum_contents
                    csum.filename = md.filename_contents
                    rel.add_checksum(csum)

            # add screenshot
            if md.screenshot_caption:
                ss = appstream.Screenshot()
                ss.caption = md.screenshot_caption
                if md.screenshot_url:
                    im = appstream.Image()
                    im.url = md.screenshot_url
                    ss.add_image(im)
                component.add_screenshot(ss)

            # add requires for each allowed vendor_ids
            user_item = db_users.get_item(item.qa_group)
            if user_item.vendor_ids:
                req = appstream.Require()
                req.kind = 'firmware'
                req.value = 'vendor-id'
                if len(user_item.vendor_ids) == 1:
                    req.compare = 'eq'
                else:
                    req.compare = 'regex'
                req.version = '|'.join(user_item.vendor_ids)
                component.add_require(req)

            # add component
            store.add(component)

    # dump to file
    download_dir = app.config['DOWNLOAD_DIR']
    if not os.path.exists(download_dir):
        os.mkdir(download_dir)
    filename = os.path.join(download_dir, filename)
    store.to_file(filename)

    # upload to the CDN
    blob = open(filename, 'rb').read()
    _upload_to_cdn(filename, blob)

    # generate and upload the detached signature
    if affidavit:
        blob_asc = affidavit.create(blob)
        _upload_to_cdn(filename + '.asc', blob_asc)

def metadata_update_qa_group(qa_group):
    """ updates metadata for a specific qa_group """

    # explicit
    affidavit = create_affidavit()
    if qa_group:
        filename = 'firmware-%s.xml.gz' % _qa_hash(qa_group)
        _generate_metadata_kind(filename,
                                qa_group=qa_group,
                                affidavit=affidavit)
        return

    # do for all
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    qa_groups = db_firmware.get_qa_groups()
    for qa_group in qa_groups:
        filename_qa = 'firmware-%s.xml.gz' % _qa_hash(qa_group)
        _generate_metadata_kind(filename_qa,
                                qa_group=qa_group,
                                affidavit=affidavit)

def metadata_update_targets(targets):
    """ updates metadata for a specific target """
    affidavit = create_affidavit()
    for target in targets:
        if target == 'stable':
            _generate_metadata_kind('firmware.xml.gz',
                                    targets=['stable'],
                                    affidavit=affidavit)
        elif target == 'testing':
            _generate_metadata_kind('firmware-testing.xml.gz',
                                    targets=['stable', 'testing'],
                                    affidavit=affidavit)

def _hashfile(afile, hasher, blocksize=65536):
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.hexdigest()

def metadata_update_pulp():
    """ updates metadata for Pulp """
    db = LvfsDatabase(os.environ)
    db_firmware = LvfsDatabaseFirmware(db)
    items = db_firmware.get_items()
    files_to_scan = []
    files_to_scan.append('firmware.xml.gz')
    files_to_scan.append('firmware.xml.gz.asc')
    for item in items:
        if item.target != 'stable':
            continue
        files_to_scan.append(item.filename)

    # for each file in stable plus metadata
    data = []
    download_dir = app.config['DOWNLOAD_DIR']
    for f in files_to_scan:
        fn = os.path.join(download_dir, f)
        if not os.path.exists(fn):
            continue

        # filename,sha256,size
        sha256 = _hashfile(open(fn, 'rb'), hashlib.sha256())
        fn_sz = os.path.getsize(fn)
        data.append('%s,%s,%i\n' % (f, sha256, fn_sz))

    # write file
    filename = os.path.join(download_dir, 'PULP_MANIFEST')
    f = open(filename, 'w')
    f.writelines(data)
    f.close()

    # upload to CDN
    blob = open(filename, 'rb').read()
    _upload_to_cdn(filename, blob)
    return
