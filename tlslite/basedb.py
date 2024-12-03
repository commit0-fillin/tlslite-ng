"""Base class for SharedKeyDB and VerifierDB."""
try:
    import anydbm
except ImportError:
    import dbm as anydbm
import threading
import time
import logging

class BaseDB(object):

    def __init__(self, filename, type):
        self.type = type
        self.filename = filename
        if self.filename:
            self.db = None
        else:
            self.db = {}
        self.lock = threading.Lock()

    def create(self):
        """
        Create a new on-disk database.

        :raises anydbm.error: If there's a problem creating the database.
        """
        if self.filename:
            self.lock.acquire()
            try:
                self.db = anydbm.open(self.filename, 'n')
            except anydbm.error as e:
                raise anydbm.error(f"Error creating database: {str(e)}")
            finally:
                self.lock.release()
        else:
            self.db = {}

    def open(self):
        """
        Open a pre-existing on-disk database.

        :raises anydbm.error: If there's a problem opening the database.
        :raises ValueError: If the database is not of the right type.
        """
        if self.filename:
            self.lock.acquire()
            try:
                self.db = anydbm.open(self.filename, 'w')
                if self.type not in self.db:
                    raise ValueError(f"Database is not of type {self.type}")
            except anydbm.error as e:
                raise anydbm.error(f"Error opening database: {str(e)}")
            finally:
                self.lock.release()
        else:
            raise ValueError("Cannot open in-memory database")

    def __getitem__(self, username):
        if self.db == None:
            raise AssertionError('DB not open')
        self.lock.acquire()
        try:
            valueStr = self.db[username]
        finally:
            self.lock.release()
        return self._getItem(username, valueStr)

    def __setitem__(self, username, value):
        if self.db == None:
            raise AssertionError('DB not open')
        valueStr = self._setItem(username, value)
        self.lock.acquire()
        try:
            self.db[username] = valueStr
            if self.filename:
                self.db.sync()
        finally:
            self.lock.release()

    def __delitem__(self, username):
        if self.db == None:
            raise AssertionError('DB not open')
        self.lock.acquire()
        try:
            del self.db[username]
            if self.filename:
                self.db.sync()
        finally:
            self.lock.release()

    def __contains__(self, username):
        """
        Check if the database contains the specified username.

        :param str username: The username to check for.

        :rtype: bool
        :returns: True if the database contains the username, False
            otherwise.
        """
        if self.db == None:
            raise AssertionError('DB not open')
        self.lock.acquire()
        try:
            return username in self.db
        finally:
            self.lock.release()

    def keys(self):
        """
        Return a list of usernames in the database.

        :rtype: list
        :returns: The usernames in the database.
        """
        if self.db is None:
            raise AssertionError('DB not open')
        self.lock.acquire()
        try:
            return list(self.db.keys())
        finally:
            self.lock.release()
