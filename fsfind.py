'''Find files and directories in a file system'''

import sys, os, re, warnings, operator
from os import lstat, stat
from os.path import normpath, join
from datetime import datetime
from operator import attrgetter
from collections import namedtuple
from errno import ENOENT
from stat import S_IFDIR, S_IFLNK, S_IFREG


if sys.version_info >= (3,):
    PYTHON3 = True
else:
    PYTHON3 = False


if PYTHON3:
    basestring = str
    from os import scandir
else:
    from scandir import scandir


class GenericDirEntry(object):
    '''Wrapper to create a DirEntry like object from a plain path
    
    Copied from the 'scandir' module that predated its inclusion in the stdlib
    (and is the only way to get it on 2.7), since there is no equivalent 
    functionality in the stdlib.    
    '''
    __slots__ = ('name', '_stat', '_lstat', '_scandir_path', '_path')

    def __init__(self, scandir_path, name):
        self._scandir_path = scandir_path
        self.name = name
        self._stat = None
        self._lstat = None
        self._path = None

    @property
    def path(self):
        if self._path is None:
            self._path = join(self._scandir_path, self.name)
        return self._path

    def stat(self, follow_symlinks=True):
        if follow_symlinks:
            if self._stat is None:
                self._stat = stat(self.path)
            return self._stat
        else:
            if self._lstat is None:
                self._lstat = lstat(self.path)
            return self._lstat

    def is_dir(self, follow_symlinks=True):
        try:
            st = self.stat(follow_symlinks=follow_symlinks)
        except OSError as e:
            if e.errno != ENOENT:
                raise
            return False  # Path doesn't exist or is a broken symlink
        return st.st_mode & 0o170000 == S_IFDIR

    def is_file(self, follow_symlinks=True):
        try:
            st = self.stat(follow_symlinks=follow_symlinks)
        except OSError as e:
            if e.errno != ENOENT:
                raise
            return False  # Path doesn't exist or is a broken symlink
        return st.st_mode & 0o170000 == S_IFREG

    def is_symlink(self):
        try:
            st = self.stat(follow_symlinks=False)
        except OSError as e:
            if e.errno != ENOENT:
                raise
            return False  # Path doesn't exist or is a broken symlink
        return st.st_mode & 0o170000 == S_IFLNK

    def inode(self):
        st = self.stat(follow_symlinks=False)
        return st.st_ino

    def __str__(self):
        return '<{0}: {1!r}>'.format(self.__class__.__name__, self.name)

    __repr__ = __str__


class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class NoMatchType(object):
    '''Singleton that can be returned by rules to indicate they did not match
    the given input.'''
    __metaclass__ = Singleton

    def __nonzero__(self):
        return False

    __bool__ = __nonzero__


NoMatch = NoMatchType()


def make_regex_rule(regex_str):
    '''Make a rule to match based on a regex pattern

    The returned 'match_info' will be a list containing the full regex match
    plus any matched subgroups.
    '''
    regex = re.compile(regex_str)
    def rule(path, dir_entry):
        result = regex.search(path)
        if result:
            return [result.group()] + list(result.groups())
        return NoMatch

    return rule


def get_comp_op(op_str):
    if op_str == '<':
        return operator.lt
    elif op_str == '<=':
        return operator.le
    elif op_str == '>':
        return operator.gt
    elif op_str == '>=':
        return operator.ge
    else:
        raise ValueError("Invalid comparison operator: %s" % op_str)


def make_age_rule(comp, delta, stat_field='mtime', now=None, follow_symlinks=False):
    '''Make a rule to match based on age of time stamps'''
    comp_op = get_comp_op(comp)
    stat_attr = 'st_' + stat_field
    def rule(path, dir_entry):
        st = dir_entry.stat(follow_symlinks=follow_symlinks)
        file_dt = datetime.fromtimestamp(getattr(st, stat_attr))
        if now is not None:
            ref = now
        else:
            ref = datetime.now()
        return comp_op(ref - file_dt, delta)
    return rule


def default_match_rule(path, dir_entry):
    '''Matches anything and returns None as the 'match_info'.'''
    return None


def warn_on_error(oserror):
    '''The default callback function for scandir errors. Raises a
    warning.

    Can be overridden with any function that takes a single argument
    (the OSError exception).'''
    warnings.warn('Error on listdir: ' + str(oserror))


MatchResult = namedtuple('MatchResult', 'path dir_entry match_info')
'''The return type for `FsFinder.matches`. Contains the path (relative or 
absolute depending on the `root_path` supplied to `FsFinder.matches`), the
`scandir.DirEntry` object, and the return value from the match rule.'''


class FsFinder(object):
    '''Object which contains a number of 'rules' that define how it will
    traverse a directory structure and what paths it will yield. The FsFinder 
    object can then be used to generate matches starting from one or more 
    root paths.

    Each 'rule' is a callable that takes two arguments, the path and the
    corresponding DirEntry object. The path may be relative or 
    absolute depending on the supplied root_path. Any rule can also be 
    provided as a string, in which case it will be converted to a callable 
    using `make_regex_rule`.

    Parameters
    ----------
    match_rule : callable
        Returns the 'match_info' result or `NoMatch` if the path should be
        ignored. If None the `default_match_rule` will be used.

    ignore_rules : list of callable
        If any of these callables return a value that evaluates to True the
        path will be ignored. The first rule that returns True will cause all
        subsequent `ignore_rules` and the `match_rule` to be skipped.

    prune_rules : list of callable
        If a path is a directory and any of these callables return a value
        that evaluates to True the directory will not be descended into. The
        directory path itself may still be matched.

    depth : tuple or int
        The minimum and maximum depth for recursion. If an single int is
        given only paths at that depth will be generated.

    sort : bool
        If true the paths in each directory will be processed and generated
        in sorted order.

    on_error : callable
        Callback for errors from scandir. The errors are typically due to a
        directory being deleted between being found and being recursed into.

    follow_symlinks : bool
        Follow symbolic links. If set to True it is possible to get stuck in
        an infinite loop.

    '''
    def __init__(self, match_rule=None, ignore_rules=None, prune_rules=None,
                 depth=(0,None), sort=False, on_error=None,
                 follow_symlinks=False):

        if match_rule is None:
            match_rule = default_match_rule
        self.match_rule = match_rule
        if ignore_rules:
            self.ignore_rules = ignore_rules[:]
        else:
            self.ignore_rules = []
        if prune_rules:
            self.prune_rules = prune_rules[:]
        else:
            self.prune_rules = []
        if not isinstance(depth, tuple):
            depth = (depth, depth)
        if depth[0] < 0:
            raise ValueError("The minimum depth must be positive")
        if not depth[1] is None and depth[1] < depth[0]:
            raise ValueError("The maximum depth must be None or greater than "
                             "the minimum")
        self.depth = depth
        self.sort = sort
        self.on_error = on_error
        self.follow_symlinks = follow_symlinks

    def _convert_regex_rules(self):
        if isinstance(self.match_rule, basestring):
            self.match_rule = make_regex_rule(self.match_rule)
        for index, rule in enumerate(self.ignore_rules):
            if isinstance(rule, basestring):
                self.ignore_rules[index] = make_regex_rule(rule)
        for index, rule in enumerate(self.prune_rules):
            if isinstance(rule, basestring):
                self.prune_rules[index] = make_regex_rule(rule)

    def _test_target_path(self, path, dir_entry):
        for rule in self.ignore_rules:
            if bool(rule(path, dir_entry)) == True:
                return NoMatch
        result = self.match_rule(path, dir_entry)
        return result

    def matches(self, root_paths, dir_entries=None):
        '''Generate matches by recursively walking from the 'root_paths' down
        into the directory structure(s).

        The object's rules define which paths cause a result to be generated, 
        and the `match_rule` provides the `match_info` attribute in the 
        generated `MatchResult` object.

        Parameters
        ----------
        root_paths : iter
            Provides the paths to start our walk from. If you want these to
            be processed into sorted order you must sort them yourself.

        dir_entries : list or None
            If given, must provide a scandir.DirEntry for each root path. If
            not provided we must call stat for each root path.

        Returns
        -------
        result : MatchResult
            A `MatchResult` object is generated for each matched path.
        '''
        # Allow a single path or an iterable to be passed
        if isinstance(root_paths, basestring):
            root_paths = [root_paths]
            if dir_entries is not None:
                dir_entries = [dir_entries]

        # Make sure any regex rules have been converted to a callable
        self._convert_regex_rules()

        # Crawl through each root path
        for root_idx, root_path in enumerate(root_paths):
            # Get rid of any extra path seperators
            root_path = normpath(root_path)

            # Get the corresponding DirEntry
            if dir_entries is None:
                p, name = os.path.split(root_path)
                if p == '':
                    p = '.'
                root_entry = GenericDirEntry(p, name)
            else:
                root_entry = dir_entries[root_idx]

            # Check if the root path itself is matched
            if self.depth[0] == 0:
                match_info = self._test_target_path(root_path, root_entry)
                if not match_info is NoMatch:
                    yield MatchResult(root_path, root_entry, match_info)
                if not root_entry.is_dir():
                    continue

            # Check if the root_path is pruned
            prune_root = False
            for rule in self.prune_rules:
                if rule(root_path, root_entry):
                    prune_root = True
                    break
            if prune_root:
                continue

            # Walk through directory structure checking paths against
            # rules
            curr_dir = (root_path, root_entry)
            next_dirs = []
            while True:
                # Determine the current depth from the root_path
                curr_depth = (curr_dir[0].count(os.sep) -
                              root_path.count(os.sep)) + 1

                #Build a list of entries for this level so we can sort if
                #requested
                curr_entries = []

                # Try getting the contents of the current directory
                try:
                    for e in scandir(curr_dir[0]):
                        # Keep directories under the depth limit so we can
                        # resurse into them
                        if e.is_dir():
                            if (self.depth[1] is not None and
                                curr_depth > self.depth[1]
                               ):
                                continue
                        else:
                            # Plain files can be ignored if they violate
                            # either depth limit
                            if (curr_depth < self.depth[0] or
                                (self.depth[1] is not None and
                                 curr_depth > self.depth[1])
                               ):
                                continue

                        #Add to the list of entries for the curr_dir
                        curr_entries.append(e)

                except OSError as error:
                    #Handle errors from the scandir call
                    if self.on_error is not None:
                        self.on_error(error)
                    else:
                        raise
                else:
                    # Sort the entries if requested
                    if self.sort:
                        curr_entries.sort(key=attrgetter('name'))

                    # Iterate through the entries, yielding them if they are a
                    # match
                    for e in curr_entries:
                        p = join(curr_dir[0], e.name)

                        if e.is_dir(follow_symlinks=self.follow_symlinks):
                            # If it is not pruned, add it to next_dirs. 
                            for rule in self.prune_rules:
                                if rule(p, e):
                                    break
                            else:
                                next_dirs.append((p, e))

                            # If we are below min depth we don't try matching
                            # the dir
                            if curr_depth < self.depth[0]:
                                continue

                        # Test the path against the match/ignore rules
                        match_info = self._test_target_path(p, e)
                        if not match_info is NoMatch:
                            yield MatchResult(p, e, match_info)

                # Update curr_dir or break if we are done
                try:
                    curr_dir = next_dirs.pop(0)
                except IndexError:
                    break
