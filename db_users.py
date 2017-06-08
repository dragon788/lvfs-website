#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import MySQLdb as mdb
import hashlib

from db import CursorError

def _password_hash(value):
    """ Generate a salted hash of the password string """
    salt = 'lvfs%%%'
    return hashlib.sha1(salt + value).hexdigest()

def _create_user_item(e):
    """ Create a user object from the results """
    item = LvfsUser()
    item.username = e[0]
    item.display_name = e[1]
    item.email = e[2]
    item.password = e[3]
    item.is_enabled = bool(e[4])
    item.is_qa = bool(e[5])
    item.qa_group = e[6]
    item.is_locked = bool(e[7])
    item.pubkey = e[8]
    if e[9]:
        item.vendor_ids = e[9].split(',')
    return item

class LvfsUser(object):
    def __init__(self):
        """ Constructor for object """
        self.username = None
        self.password = None
        self.display_name = None
        self.email = None
        self.is_enabled = False
        self.is_qa = False
        self.qa_group = None
        self.is_locked = False
        self.pubkey = None
        self.vendor_ids = []

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.username)

    def __repr__(self):
        return "LvfsUser object %s" % self.username

class LvfsDatabaseUsers(object):

    def __init__(self, db):
        """ Constructor for object """
        self._db = db

    def get_signing_uid(self):
        """ Gets the signing UID for the site, i.e. the admin email address """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT email FROM users WHERE username='admin'")
        except mdb.Error as e:
            raise CursorError(cur, e)
        key_uid = cur.fetchone()
        return key_uid[0]

    def add(self, username, password, name, email, qa_group):
        """ Adds the user to the userlist """
        assert username
        assert password
        assert name
        assert email
        assert qa_group
        pw_hash = _password_hash(password)
        try:
            cur = self._db.cursor()
            cur.execute("INSERT INTO users (username, password, display_name, "
                        "email, is_enabled, qa_group) "
                        "VALUES (%s, %s, %s, %s, 1, %s);",
                        (username, pw_hash, name, email, qa_group,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def remove(self, username):
        """ Removes the user from the userlist """
        assert username
        try:
            cur = self._db.cursor()
            cur.execute("DELETE FROM users WHERE username=%s;", (username,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def set_property(self, username, key, value):
        """ Sets some properties on the user """
        assert username
        assert key

        cur = self._db.cursor()
        try:
            query = "UPDATE users SET %s=%%s WHERE username=%%s;" % key
            if key == 'password':
                value = _password_hash(value)
            cur.execute(query, (value, username,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def is_enabled(self, username):
        """ Returns success if the username is present and enabled """
        assert username
        cur = self._db.cursor()
        try:
            cur.execute("SELECT is_enabled FROM users WHERE username=%s", (username,))
        except mdb.Error as e:
            raise CursorError(cur, e)
        auth = cur.fetchone()
        if auth:
            return True
        return False

    def verify(self, username, password):
        """ Verify that a username and password exists """
        assert username
        assert password
        pw_hash = _password_hash(password)
        try:
            cur = self._db.cursor()
            cur.execute("SELECT is_enabled FROM users WHERE username=%s AND password=%s;",
                        (username, pw_hash,))
        except mdb.Error as e:
            raise CursorError(cur, e)
        auth = cur.fetchone()
        if not auth:
            return False
        return True

    def update(self, username, password, name, email, pubkey):
        """ Update user details """
        assert username
        assert password
        assert name
        assert email
        try:
            cur = self._db.cursor()
            cur.execute("UPDATE users SET display_name=%s, email=%s, password=%s, pubkey=%s "
                        "WHERE username=%s;",
                        (name, email, _password_hash(password), pubkey, username,))
        except mdb.Error as e:
            raise CursorError(cur, e)

    def get_items(self):
        """ Get all the users """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT username, display_name, email, password, "
                        "is_enabled, is_qa, qa_group, is_locked, pubkey, vendor_ids FROM users;")
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchall()
        if not res:
            return []
        items = []
        for e in res:
            items.append(_create_user_item(e))
        return items

    def get_item(self, username, password=None):
        """ Gets information about a specific user """
        assert username
        try:
            cur = self._db.cursor()
            if password:
                cur.execute("SELECT username, display_name, email, password, "
                            "is_enabled, is_qa, qa_group, is_locked, pubkey, vendor_ids FROM users "
                            "WHERE username = %s AND password = %s LIMIT 1;",
                            (username, password,))
            else:
#                cur.execute("ALTER TABLE users ADD vendor_ids VARCHAR(4096) DEFAULT NULL")
                cur.execute("SELECT username, display_name, email, password, "
                            "is_enabled, is_qa, qa_group, is_locked, pubkey, vendor_ids FROM users "
                            "WHERE username = %s LIMIT 1;",
                            (username,))
        except mdb.Error as e:
            raise CursorError(cur, e)
        res = cur.fetchone()
        if not res:
            return None
        return _create_user_item(res)

    def get_qa_groups(self):
        """ Gets the list of QA groups """
        try:
            cur = self._db.cursor()
            cur.execute("SELECT DISTINCT qa_group FROM users;")
        except mdb.Error as e:
            raise CursorError(cur, e)
        qa_groups = []
        res = cur.fetchall()
        if not res:
            return qa_groups
        for e in res:
            qa_groups.append(e[0])
        return qa_groups
