# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/nexB/scancode.io
# The ScanCode.io software is licensed under the Apache License version 2.0.
# Data generated with ScanCode.io is provided as-is without warranties.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# Data Generated with ScanCode.io is provided on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. No content created from
# ScanCode.io should be considered or used as legal advice. Consult an Attorney
# for any legal advice.
#
# ScanCode.io is a free software code scanning tool from nexB Inc. and others.
# Visit https://github.com/nexB/scancode.io for support and download.

from scanpipe.pipelines import Pipeline
from scanpipe.pipes import d2d
from scanpipe.pipes import scancode
from scanpipe.pipes import purldb
from scanpipe import pipes

class MatchToPurlDB(Pipeline):
    """
    Match an existing to/ codebase to the PurlDB
    """

    @classmethod
    def steps(cls):
        return (
            cls.get_inputs,
            cls.extract_inputs_to_codebase_directory,
            cls.extract_archives_in_place,
            cls.collect_and_create_codebase_resources,
            cls.match_archives_to_purldb_packages,
            # cls.match_archives_to_purldb_resources,
            cls.match_resources_to_purldb,
            cls.pick_best_packages,
            cls.remove_packages_without_resources,
        )

    purldb_resource_extensions = [
        ".map",
        ".js",
        ".mjs",
        ".ts",
        ".d.ts",
        ".jsx",
        ".tsx",
        ".css",
        ".scss",
        ".less",
        ".sass",
        ".soy",
        ".class",
    ]

    def get_inputs(self):
        """Locate the ``from`` and ``to`` input files."""
        self.from_files, self.to_files = d2d.get_inputs(self.project)

    def extract_inputs_to_codebase_directory(self):
        """Extract input files to the project's codebase/ directory."""
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project.codebase_path / d2d.FROM),
            (self.to_files, self.project.codebase_path / d2d.TO),
        ]

        errors = []
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                errors += scancode.extract_archive(input_file_path, codebase_path)

        if errors:
            self.add_error("\n".join(errors))

    def extract_archives_in_place(self):
        """Extract recursively from* and to* archives in place with extractcode."""
        extract_errors = scancode.extract_archives(
            self.project.codebase_path,
            recurse=self.env.get("extract_recursively", True),
        )

        if extract_errors:
            self.add_error("\n".join(extract_errors))

    def collect_and_create_codebase_resources(self):
        """Collect and create codebase resources."""
        pipes.collect_and_create_codebase_resources(self.project)

    def match_archives_to_purldb_packages(self):
        """Match archives to PurlDB package archives."""
        if not purldb.is_available():
            self.log("PurlDB is not available. Skipping.")
            return

        match_purldb_resources(
            project=self.project,
            is_archive=True,
            matcher_func=d2d.match_purldb_package,
            logger=self.log,
        )

    def match_archives_to_purldb_resource(self):
        """Match archives to PurlDB resources."""
        if not purldb.is_available():
            self.log("PurlDB is not available. Skipping.")
            return

        match_purldb_resources(
            project=self.project,
            is_archive=True,
            matcher_func=d2d.match_purldb_resource,
            logger=self.log,
        )

    def match_resources_to_purldb(self):
        """Match files to PurlDB."""
        if not purldb.is_available():
            self.log("PurlDB is not available. Skipping.")
            return

        match_purldb_resources(
            project=self.project,
            is_archive=False,
            matcher_func=d2d.match_purldb_resource,
            logger=self.log,
        )

    def pick_best_packages(self):
        """Choose the best package for PurlDB matched resources."""
        pick_best_packages(self.project, logger=self.log)

    def remove_packages_without_resources(self):
        """Remove packages without any resources."""
        package_without_resources = self.project.discoveredpackages.filter(
            codebase_resources__isnull=True
        )
        package_without_resources.delete()


def match_purldb_resources(
    project, is_archive, matcher_func, chunk_size=1000, logger=None
):
    """
    Match against PurlDB selecting codebase resources that are archives or not.

    Match requests are sent off in batches of 1000 SHA1s. This number is set
    using `chunk_size`.
    """
    to_resources = (
        project.codebaseresources.files()
        .to_codebase()
        .no_status()
        .has_value("sha1")
        .filter(is_archive=is_archive)
    )
    resource_count = to_resources.count()

    if logger:
        logger(
            f"Matching {resource_count:,d} resources in PurlDB, "
            f"using SHA1, is_archive: {bool(is_archive)}"
        )

    d2d._match_purldb_resources(
        project=project,
        to_resources=to_resources,
        matcher_func=matcher_func,
        chunk_size=chunk_size,
        logger=logger,
    )


def pick_best_packages(project, logger=None):
    """Choose the best package for PurlDB matched resources."""
    """
    for each group in "grouped by package ignoring versions":
    for each package in group:
        if package.resources all contained in any other package of the group:
        remove the package - resource relationships

    11:20
    Some examples of groups
        pkg:maven/com.liferay/com.liferay.blogs.api@5.2.0
        pkg:maven/com.liferay/com.liferay.blogs.api@5.0.0
        pkg:maven/com.liferay/com.liferay.blogs.api@5.1.0
        pkg:maven/com.liferay/com.liferay.bulk.selection.api@1.1.0
        pkg:maven/com.liferay/com.liferay.bulk.selection.api@1.0.0
        pkg:maven/com.liferay/com.liferay.message.boards.api@5.1.0
        pkg:maven/com.liferay/com.liferay.message.boards.api@5.2.0
        pkg:maven/com.liferay/com.liferay.message.boards.api@5.0.0
    """
    project_packages_namespaces_and_names = project.discoveredpackages.values_list('namespace', 'name')
    project_packages_namespaces_and_names = set(project_packages_namespaces_and_names)

    for namespace, name in project_packages_namespaces_and_names:
        related_packages = project.discoveredpackages.filter(namespace=namespace, name=name)

        main_package = None
        main_package_resources_count = 0
        resource_paths_by_package = {}
        for related_package in related_packages:
            related_resource_paths = [r.path for r in related_package.resources]
            related_resource_paths_count = len(related_resource_paths)
            if related_resource_paths_count > main_package_resources_count:
                main_package_resources_count = related_resource_paths_count
                main_package = related_package
            resource_paths_by_package[related_package] = set(related_resource_paths)

        main_package_resouce_paths = resource_paths_by_package[main_package]

        for related_package in related_packages.exclude(pk=main_package.pk):
            resource_paths = resource_paths_by_package[related_package]
            if resource_paths.issubset(main_package_resouce_paths):
                related_package.codebase_resources.clear()
