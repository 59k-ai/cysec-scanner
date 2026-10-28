# Copyright 2026 59k GmbH
# SPDX-License-Identifier: Apache-2.0
#
# Tests for the two GUI CI gates: check_ts_complete.py (translation
# completeness) and check_vocabulary.py (SGUI-06 vocabulary + plain-text
# rendering). Stdlib unittest only, so the gates stay testable on any runner
# without a Qt install:
#
#     python3 -m unittest gui/tools/test_gates.py -v
#
# Each case writes small inline fixtures into a temporary directory and runs
# the gate as a subprocess, asserting on the exit code and the output, which
# is exactly how CI consumes them.

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

TOOLS = os.path.dirname(os.path.abspath(__file__))
TS_GATE = os.path.join(TOOLS, "check_ts_complete.py")
VOCAB_GATE = os.path.join(TOOLS, "check_vocabulary.py")


def run(*args):
    proc = subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def ts_doc(messages, language="de"):
    body = textwrap.dedent(messages).strip("\n")
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<!DOCTYPE TS>\n"
        f'<TS version="2.1" language="{language}" sourcelanguage="en">\n'
        "<context>\n"
        "    <name>Fixture</name>\n"
        f"{body}\n"
        "</context>\n"
        "</TS>\n"
    )


class TempTree(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, relpath, content):
        path = os.path.join(self.root, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path


class TsCompleteTests(TempTree):
    FINISHED = """
        <message>
            <source>Start scan</source>
            <translation>Scan starten</translation>
        </message>
    """

    def test_finished_file_passes(self):
        path = self.write("a_de.ts", ts_doc(self.FINISHED))
        code, out = run(TS_GATE, path)
        self.assertEqual(code, 0, out)
        self.assertIn("TS_COMPLETE", out)

    def test_unfinished_fails_and_names_source(self):
        path = self.write("a_de.ts", ts_doc("""
            <message>
                <source>Stop scan</source>
                <translation type="unfinished">Scan stoppen</translation>
            </message>
        """))
        code, out = run(TS_GATE, path)
        self.assertEqual(code, 1, out)
        self.assertIn("Stop scan", out)
        self.assertNotIn("TS_COMPLETE", out)

    def test_vanished_fails(self):
        path = self.write("a_de.ts", ts_doc("""
            <message>
                <source>Old string</source>
                <translation type="vanished">Alt</translation>
            </message>
        """))
        code, out = run(TS_GATE, path)
        self.assertEqual(code, 1, out)

    def test_obsolete_fails(self):
        path = self.write("a_de.ts", ts_doc("""
            <message>
                <source>Old string</source>
                <translation type="obsolete">Alt</translation>
            </message>
        """))
        code, out = run(TS_GATE, path)
        self.assertEqual(code, 1, out)

    def test_missing_translation_element_fails(self):
        path = self.write("a_de.ts", ts_doc("""
            <message>
                <source>Lonely</source>
            </message>
        """))
        code, out = run(TS_GATE, path)
        self.assertEqual(code, 1, out)

    def test_empty_translation_fails(self):
        path = self.write("a_de.ts", ts_doc("""
            <message>
                <source>Close</source>
                <translation></translation>
            </message>
        """))
        code, out = run(TS_GATE, path)
        self.assertEqual(code, 1, out)
        self.assertIn("Close", out)

    def test_empty_numerusform_fails(self):
        path = self.write("a_de.ts", ts_doc("""
            <message numerus="yes">
                <source>%n host(s) found</source>
                <translation>
                    <numerusform>%n Host gefunden</numerusform>
                    <numerusform></numerusform>
                </translation>
            </message>
        """))
        code, out = run(TS_GATE, path)
        self.assertEqual(code, 1, out)

    def test_placeholder_mismatch_fails(self):
        path = self.write("a_de.ts", ts_doc("""
            <message>
                <source>%1 of %2</source>
                <translation>%1 von</translation>
            </message>
        """))
        code, out = run(TS_GATE, path)
        self.assertEqual(code, 1, out)
        self.assertIn("placeholder", out)

    def test_placeholder_mismatch_in_one_numerusform_fails(self):
        path = self.write("a_de.ts", ts_doc("""
            <message numerus="yes">
                <source>%n host(s) found</source>
                <translation>
                    <numerusform>Ein Host gefunden</numerusform>
                    <numerusform>%n Hosts gefunden</numerusform>
                </translation>
            </message>
        """))
        code, out = run(TS_GATE, path)
        self.assertEqual(code, 1, out)
        self.assertIn("placeholder", out)

    def test_numerus_with_n_in_every_form_passes(self):
        path = self.write("a_de.ts", ts_doc("""
            <message numerus="yes">
                <source>%n host(s) found</source>
                <translation>
                    <numerusform>%n Host gefunden</numerusform>
                    <numerusform>%n Hosts gefunden</numerusform>
                </translation>
            </message>
        """))
        code, out = run(TS_GATE, path)
        self.assertEqual(code, 0, out)
        self.assertIn("TS_COMPLETE", out)

    def test_reordered_placeholders_pass(self):
        path = self.write("a_de.ts", ts_doc("""
            <message>
                <source>Stage %1 of 3: %2</source>
                <translation>%2 (Phase %1 von 3)</translation>
            </message>
        """))
        code, out = run(TS_GATE, path)
        self.assertEqual(code, 0, out)

    def test_every_file_is_checked(self):
        good = self.write("good_de.ts", ts_doc(self.FINISHED))
        bad = self.write("bad_en.ts", ts_doc("""
            <message numerus="yes">
                <source>%n error(s)</source>
                <translation type="unfinished">
                    <numerusform></numerusform>
                    <numerusform></numerusform>
                </translation>
            </message>
        """, language="en"))
        code, out = run(TS_GATE, good, bad)
        self.assertEqual(code, 1, out)
        self.assertIn("bad_en.ts", out)
        code, out = run(TS_GATE, bad, good)
        self.assertEqual(code, 1, out)
        self.assertIn("bad_en.ts", out)

    def test_no_arguments_is_a_usage_error(self):
        code, _ = run(TS_GATE)
        self.assertEqual(code, 2)


class VocabularyTests(TempTree):
    def vocab(self, *extra):
        return run(VOCAB_GATE, self.root, *extra)

    def test_clean_tree_passes(self):
        self.write("src/A.qml", 'Item { property string t: qsTr("Start scan") }\n')
        code, out = self.vocab()
        self.assertEqual(code, 0, out)
        self.assertIn("VOCABULARY_CLEAN", out)

    def test_banned_word_in_qml_qstr_fails(self):
        self.write("src/A.qml", 'Item { property string t: qsTr("Sync now") }\n')
        code, out = self.vocab()
        self.assertEqual(code, 1, out)
        self.assertIn("A.qml", out)
        self.assertNotIn("VOCABULARY_CLEAN", out)

    def test_word_boundary_allows_repair(self):
        self.write("src/A.qml", 'Item { property string t: qsTr("Repair") }\n')
        code, out = self.vocab()
        self.assertEqual(code, 0, out)

    def test_multi_word_term_across_whitespace_fails(self):
        self.write("src/A.qml", 'Item { property string t: qsTr("Enter your API   key") }\n')
        code, out = self.vocab()
        self.assertEqual(code, 1, out)

    def test_qstranslate_in_cpp_fails(self):
        self.write("src/a.cpp", 'auto s = qsTranslate("Ctx", "Open the dashboard");\n')
        code, out = self.vocab()
        self.assertEqual(code, 1, out)

    def test_german_banned_word_in_translation_fails(self):
        self.write("i18n/x_de.ts", ts_doc("""
            <message>
                <source>Settings</source>
                <translation>Konto</translation>
            </message>
        """))
        code, out = self.vocab()
        self.assertEqual(code, 1, out)
        self.assertIn("x_de.ts", out)

    def test_banned_word_in_numerusform_fails(self):
        self.write("i18n/x_en.ts", ts_doc("""
            <message numerus="yes">
                <source>%n host(s)</source>
                <translation>
                    <numerusform>%n host</numerusform>
                    <numerusform>%n verdicts</numerusform>
                </translation>
            </message>
        """, language="en"))
        code, out = self.vocab()
        self.assertEqual(code, 1, out)

    def test_banned_word_in_gui_doc_fails(self):
        self.write("README.md", "Paste the token here.\n")
        code, out = self.vocab()
        self.assertEqual(code, 1, out)
        self.assertIn("README.md", out)

    def test_code_identifiers_are_not_scanned(self):
        self.write(
            "src/A.qml",
            "Item {\n"
            "    property var tokenizer: null\n"
            "    property bool sync: false // not user-visible\n"
            '    property string label: qsTr("Hosts")\n'
            "}\n",
        )
        self.write("src/b.cpp", "int account = 0; // engine-side counter\n")
        code, out = self.vocab()
        self.assertEqual(code, 0, out)

    def test_build_directories_are_skipped(self):
        self.write("build/gen/A.qml", 'Item { property string t: qsTr("Sync now") }\n')
        self.write("build-610/notes.md", "cloud\n")
        code, out = self.vocab()
        self.assertEqual(code, 0, out)

    def test_plaintext_not_run_without_flag(self):
        self.write("src/A.qml", "Item { Text { text: modelData } }\n")
        code, out = self.vocab()
        self.assertEqual(code, 0, out)
        self.assertNotIn("PLAINTEXT_CLEAN", out)


class PlainTextTests(TempTree):
    def plaintext(self):
        return run(VOCAB_GATE, self.root, "--plaintext")

    def test_rich_text_format_fails(self):
        self.write(
            "src/A.qml",
            "Item {\n    PlainLabel { textFormat: Text.RichText }\n}\n",
        )
        code, out = self.plaintext()
        self.assertEqual(code, 1, out)
        self.assertIn("RichText", out)

    def test_bare_text_fails(self):
        self.write("src/A.qml", "Item {\n    Text { text: modelData }\n}\n")
        code, out = self.plaintext()
        self.assertEqual(code, 1, out)
        self.assertIn("A.qml", out)

    def test_plain_text_passes(self):
        self.write(
            "src/A.qml",
            "Item {\n    Text { textFormat: Text.PlainText; text: x }\n}\n",
        )
        code, out = self.plaintext()
        self.assertEqual(code, 0, out)
        self.assertIn("VOCABULARY_CLEAN", out)
        self.assertIn("PLAINTEXT_CLEAN", out)

    def test_plain_label_passes(self):
        self.write("src/A.qml", "Item {\n    PlainLabel { }\n}\n")
        code, out = self.plaintext()
        self.assertEqual(code, 0, out)
        self.assertIn("PLAINTEXT_CLEAN", out)

    def test_content_item_text_without_format_fails(self):
        self.write(
            "src/A.qml",
            "Button {\n    contentItem: Text {\n        text: parent.text\n    }\n}\n",
        )
        code, out = self.plaintext()
        self.assertEqual(code, 1, out)

    def test_child_format_does_not_cover_parent(self):
        self.write(
            "src/A.qml",
            "Label {\n"
            "    text: x\n"
            "    Text { textFormat: Text.PlainText; text: y }\n"
            "}\n",
        )
        code, out = self.plaintext()
        self.assertEqual(code, 1, out)

    def test_braces_in_strings_and_comments_do_not_confuse_depth(self):
        self.write(
            "src/A.qml",
            "Item {\n"
            "    // a stray } in a comment\n"
            "    TextEdit {\n"
            '        text: "} {"\n'
            "        textFormat: TextEdit.PlainText\n"
            "    }\n"
            "}\n",
        )
        code, out = self.plaintext()
        self.assertEqual(code, 0, out)

    def test_text_edit_rich_text_fails(self):
        self.write(
            "src/A.qml",
            "TextArea {\n    textFormat: TextEdit.RichText\n}\n",
        )
        code, out = self.plaintext()
        self.assertEqual(code, 1, out)

    def test_plaintext_rules_only_cover_src(self):
        self.write("tests/qml/tst_a.qml", "Item { Text { text: modelData } }\n")
        code, out = self.plaintext()
        self.assertEqual(code, 0, out)
        self.assertIn("PLAINTEXT_CLEAN", out)


if __name__ == "__main__":
    unittest.main()
