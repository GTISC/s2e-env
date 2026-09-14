"""Tests for S2E environment initialization helpers."""

import os
import tempfile
import xml.etree.ElementTree as ET
from unittest import TestCase

from s2e_env.commands.init import _configure_s2e_revision


class S2ERevisionTestCase(TestCase):
    """Test selecting an S2E revision without changing other projects."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.source_path = self.temp_dir.name
        self.manifest_dir = os.path.join(self.source_path, '.repo',
                                         'manifests')
        os.makedirs(self.manifest_dir)
        self.default_manifest = os.path.join(self.manifest_dir, 'default.xml')
        self.default_contents = (
            b'<manifest><default revision="master" />'
            b'<project name="s2e" /><project name="decree" /></manifest>')
        with open(self.default_manifest, 'wb') as manifest:
            manifest.write(self.default_contents)

    def tearDown(self):
        self.temp_dir.cleanup()

    @property
    def override_path(self):
        return os.path.join(self.source_path, '.repo', 'local_manifests',
                            's2e-branch.xml')

    def test_branch_override_is_scoped_to_s2e(self):
        _configure_s2e_revision(self.source_path, 'behavior-exploration')

        root = ET.parse(self.override_path).getroot()
        self.assertEqual(root.tag, 'manifest')
        self.assertEqual(len(root), 1)
        self.assertEqual(root[0].tag, 'extend-project')
        self.assertEqual(root[0].attrib, {
            'name': 's2e',
            'revision': 'behavior-exploration',
        })
        with open(self.default_manifest, 'rb') as manifest:
            self.assertEqual(manifest.read(), self.default_contents)

    def test_revision_is_xml_escaped(self):
        _configure_s2e_revision(self.source_path, 'feature/a&b')

        project = ET.parse(self.override_path).getroot()[0]
        self.assertEqual(project.attrib['revision'], 'feature/a&b')

    def test_master_removes_stale_override(self):
        _configure_s2e_revision(self.source_path, 'behavior-exploration')
        self.assertTrue(os.path.exists(self.override_path))

        _configure_s2e_revision(self.source_path, 'master')

        self.assertFalse(os.path.exists(self.override_path))
