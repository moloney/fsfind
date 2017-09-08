from __future__ import print_function

import nose
from nose.tools import *
from tempfile import mkdtemp
import shutil, os, sys
from os.path import join, split


#Make sure we test the local source code rather than the installed copy
test_dir = os.path.dirname(__file__)
src_dir = os.path.normpath(os.path.join(test_dir, '..'))
sys.path.insert(0, src_dir)
import fsfind


class TestMakeRegexRule():

    known_results = {'.+':
                        {'hello': ['hello'],
                         'something.txt': ['something.txt'],
                         '': fsfind.NoMatch,
                        },
                     '(.+)\.(.+)':
                        {'something.txt': ['something.txt',
                                           'something',
                                           'txt'
                                          ],
                         'image_001.dcm': ['image_001.dcm',
                                           'image_001',
                                           'dcm'
                                          ],
                         'something': fsfind.NoMatch,
                        },
                     'image_([0-9]+)\.dcm':
                        {'image_001.dcm': ['image_001.dcm',
                                           '001'
                                          ],
                         'image_1.dcm': ['image_1.dcm',
                                         '1'
                                        ],
                         'image_one.dcm': fsfind.NoMatch,
                         'image_001.dc': fsfind.NoMatch,
                        }
                    }

    def test_known_results(self):
        for match_regex, tests in self.known_results.items():
            match_rule = fsfind.make_regex_rule(match_regex)
            for input_str, results in tests.items():
                assert(match_rule(input_str, None) == results)


def build_dir(base_dir, paths_at_level):
    for level in paths_at_level:
        for path in level:
            if split(path)[1].split('-')[-1].startswith('dir'):
                os.mkdir(join(base_dir, path))
            else:
                tmpfile = open(join(base_dir, path), 'a')
                tmpfile.close()


class TestSimpleRules():
    paths_at_level = [['level0-dir'],
                      [join('level0-dir', 'level1-file1'),
                       join('level0-dir', 'level1-file2'),
                       join('level0-dir', 'level1-dir1'),
                       join('level0-dir', 'level1-dir2'),
                      ],
                      [join('level0-dir', 'level1-dir1', 'level2-file1'),
                       join('level0-dir', 'level1-dir1', 'level2-file2'),
                       join('level0-dir', 'level1-dir1', 'level2-dir1'),
                       join('level0-dir', 'level1-dir2', 'level2-dir2'),
                       join('level0-dir', 'level1-dir2', 'level2-file3')
                      ],
                      [join('level0-dir', 'level1-dir1', 'level2-dir1',
                            'level3-file1'),
                       join('level0-dir', 'level1-dir1', 'level2-dir1',
                            'level3-dir1'),
                      ],
                      [join('level0-dir', 'level1-dir1', 'level2-dir1',
                            'level3-dir1', 'level4-file1'),
                      ],
                     ]

    def setup(self):
        self.init_dir = os.getcwd()
        self.test_dir = mkdtemp()
        build_dir(self.test_dir, self.paths_at_level)
        os.chdir(self.test_dir)

    def tearDown(self):
        os.chdir(self.init_dir)
        shutil.rmtree(self.test_dir)

    def test_min_depth(self):
        for i in range(len(self.paths_at_level)):
            ff = fsfind.FsFinder(depth=(i, None))
            matches = list(ff.matches('level0-dir'))

            total_paths = 0
            for j in range(i, len(self.paths_at_level)):
                total_paths += len(self.paths_at_level[j])
                for path in self.paths_at_level[j]:
                    assert(any(path == m.path for m in matches))

            if len(matches) != total_paths:
                print(i)
                print([m.path for m in matches])
            assert(len(matches) == total_paths)

    def test_max_depth(self):
        for i in range(len(self.paths_at_level)):
            ff = fsfind.FsFinder(depth=(0, i))
            matches = list(ff.matches('level0-dir'))

            total_paths = 0
            for j in range(0, i+1):
                total_paths += len(self.paths_at_level[j])
                for path in self.paths_at_level[j]:
                    assert(any(path == m.path for m in matches))

            assert(len(matches) == total_paths)

    def test_match_regex(self):
        for i in range(len(self.paths_at_level)):
            ff = fsfind.FsFinder('level' + str(i))
            matches = list(ff.matches('level0-dir'))

            for j in range(i, len(self.paths_at_level)):
                for path in self.paths_at_level[j]:
                    path = os.path.normpath(path)
                    assert(any(['level' + str(i)] == m.match_info
                               for m in matches)
                          )

    def test_ignore_regex(self):
        ff = fsfind.FsFinder(ignore_rules=['level0'])
        matches = list(ff.matches('level0-dir'))
        assert(len(matches) == 0)

        for i in range(1, len(self.paths_at_level)):
            ff = fsfind.FsFinder(ignore_rules=['level' + str(i)])
            matches = list(ff.matches('level0-dir'))

            for j in range(0, i):
                for path in self.paths_at_level[j]:
                    path = os.path.normpath(path)
                    assert(any(path == m.path for m in matches))

    def test_ignore_regexes(self):
        ignore_rules = ['level2-file1', '.+'+os.sep+'level3-dir1$']
        ff = fsfind.FsFinder(ignore_rules=ignore_rules)
        for match_result in ff.matches('level0-dir'):
            assert(not os.path.basename(match_result.path) in
                   ['level2-file1', 'level3-dir1'])

    def test_prune_regex(self):
        ff = fsfind.FsFinder(prune_rules=['level0-dir'])
        matches = list(ff.matches('level0-dir'))
        assert(len(matches) == 1)
        assert(matches[0].path == 'level0-dir')

        prune_rule = 'level2-dir1'
        ff = fsfind.FsFinder(prune_rules=[prune_rule])
        for match_result in ff.matches('level0-dir'):
            idx = match_result.path.find(prune_rule)
            if idx != -1:
                assert(all(x != os.sep for x in match_result.path[idx:]))

    def test_prune_regexes(self):
        prune_rules = ['level1-dir2', 'level3-dir1']
        ff = fsfind.FsFinder(prune_rules=prune_rules)
        for match_result in ff.matches('level0-dir'):
            for rule in prune_rules:
                idx = match_result.path.find(rule)
                if idx != -1:
                    assert(all(x != os.sep for x in match_result.path[idx:]))

class TestSorting():
    paths_at_level = [['c-dir', 'a-dir', 'd-file', 'b-file'],
                      [join('c-dir', 'g-file'),
                       join('c-dir', 'f-file'),
                       join('a-dir', 'y-file'),
                       join('a-dir', 'x-file'),
                      ],
                     ]

    dfs_sorted = ['.',
                  join('.', 'a-dir'),
                  join('.', 'b-file'),
                  join('.', 'c-dir'),
                  join('.', 'd-file'),
                  join('.', 'a-dir', 'x-file'),
                  join('.', 'a-dir', 'y-file'),
                  join('.', 'c-dir', 'f-file'),
                  join('.', 'c-dir', 'g-file'),
                 ]

    def setup(self):
        self.init_dir = os.getcwd()
        self.test_dir = mkdtemp()
        build_dir(self.test_dir, self.paths_at_level)
        os.chdir(self.test_dir)

    def tearDown(self):
        os.chdir(self.init_dir)
        shutil.rmtree(self.test_dir)

    def test_sorting(self):
        ff = fsfind.FsFinder(sort=True)
        matched_paths = [m.path for m in ff.matches('.')]
        assert matched_paths == self.dfs_sorted


