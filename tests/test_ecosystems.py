import tempfile
import unittest
from pathlib import Path

from bbharden import sbom
from bbharden.context import RepoContext
from bbharden.scanners.dependencies import _collect_packages


def collect(files):
    with tempfile.TemporaryDirectory() as t:
        for n, c in files.items():
            p = Path(t) / n
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(c)
        return _collect_packages(RepoContext(root=Path(t)))


class TestEcosystems(unittest.TestCase):
    def test_go_mod_block_single_indirect_and_non_requires(self):
        f = collect({"go.mod": "module x\n\ngo 1.21\n\nrequire (\n\tgithub.com/a/b v1.2.3\n"
                     "\tgolang.org/x/net v0.17.0 // indirect\n)\n\nrequire github.com/c/d v2.0.0+incompatible\n"
                     "replace github.com/a/b => ../b\nexclude github.com/z/z v1.0.0\n"})
        self.assertEqual(sorted((e, n, v) for e, n, v in f),
                         [("Go", "github.com/a/b", "1.2.3"), ("Go", "github.com/c/d", "2.0.0+incompatible"),
                          ("Go", "golang.org/x/net", "0.17.0")])

    def test_cargo_only_registry_crates(self):
        f = collect({"Cargo.lock": '[[package]]\nname = "serde"\nversion = "1.0.1"\n'
                     'source = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
                     '[[package]]\nname = "me"\nversion = "0.1.0"\n\n'
                     '[[package]]\nname = "g"\nversion = "0.2.0"\nsource = "git+https://x/y"\n'})
        self.assertEqual(list(f), [("crates.io", "serde", "1.0.1")])

    def test_maven_literals_only(self):
        f = collect({"pom.xml": "<project><!-- <dependency><groupId>no</groupId><artifactId>c</artifactId>"
                     "<version>9.9</version></dependency> -->"
                     "<dependencies><dependency><groupId>org.apache.logging.log4j</groupId>"
                     "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>"
                     "<dependency><groupId>a</groupId><artifactId>b</artifactId><version>${v}</version></dependency>"
                     "<dependency><groupId>a</groupId><artifactId>r</artifactId><version>[1,2)</version></dependency>"
                     "</dependencies></project>"})
        self.assertEqual(list(f), [("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")])

    def test_gemfile_lock_specs_only(self):
        f = collect({"Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n"
                     "      rack-dep (>= 1)\n    rails (6.0.0)\n\nDEPENDENCIES\n  rails (~> 6.0)\n"})
        self.assertEqual(sorted(f), [("RubyGems", "rack", "2.2.3"), ("RubyGems", "rails", "6.0.0")])

    def test_composer_lock(self):
        f = collect({"composer.lock": '{"packages":[{"name":"monolog/monolog","version":"v2.0.0"},'
                     '{"name":"x/dev","version":"dev-main"}],"packages-dev":[{"name":"p/q","version":"1.0.0"}]}'})
        self.assertEqual(sorted(f), [("Packagist", "monolog/monolog", "2.0.0"), ("Packagist", "p/q", "1.0.0")])

    def test_hostile_inputs_do_not_crash(self):
        collect({"go.mod": "require (\n" + "x" * 100000 + "\n", "Cargo.lock": "[[package]]" * 1000,
                 "pom.xml": "<dependency>" * 5000, "Gemfile.lock": "specs:\n" + " " * 100000,
                 "composer.lock": '{"packages": "nope"}'})

    def test_purls(self):
        self.assertEqual(sbom.purl("Go", "github.com/a/b", "1.2.3"), "pkg:golang/github.com/a/b@v1.2.3")
        self.assertEqual(sbom.purl("crates.io", "serde", "1.0.1"), "pkg:cargo/serde@1.0.1")
        self.assertEqual(sbom.purl("Maven", "g.r:a", "1"), "pkg:maven/g.r/a@1")
        self.assertEqual(sbom.purl("RubyGems", "rack", "2.2.3"), "pkg:gem/rack@2.2.3")
        self.assertEqual(sbom.purl("Packagist", "monolog/monolog", "2.0.0"), "pkg:composer/monolog/monolog@2.0.0")


if __name__ == "__main__":
    unittest.main()
