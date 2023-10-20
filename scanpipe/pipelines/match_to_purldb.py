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
from scanpipe.pipes import flag
from scanpipe.pipes import purldb


class MatchToPurlDB(Pipeline):
    """
    Match an existing to/ codebase to the PurlDB
    """

    @classmethod
    def steps(cls):
        return (
            cls.match_archives_to_purldb_packages,
            # cls.match_archives_to_purldb_resources,
            cls.match_resources_to_purldb,
            cls.pick_best_packages,
            cls.remove_packages_without_resources,
        )

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

        d2d.match_purldb_resources(
            project=self.project,
            extensions=None,
            matcher_func=d2d.match_purldb_resource,
            logger=self.log,
        )

    def pick_best_package(self):
        """Choose the best package for PurlDB matched resources."""
        pick_best_package(self.project, logger=self.log)

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


def pick_best_package(project, logger=None):
    """Choose the best package for PurlDB matched resources."""
    to_extract_directories = (
        project.codebaseresources.directories()
        .to_codebase()
        .filter(path__regex=r"^.*-extract$")
    )

    to_resources = project.codebaseresources.files().filter(
        status=flag.MATCHED_TO_PURLDB_RESOURCE
    )

    resource_count = to_extract_directories.count()

    if logger:
        logger(
            f"Refining matching for {resource_count:,d} "
            f"{flag.MATCHED_TO_PURLDB_RESOURCE} archives."
        )

    resource_iterator = to_extract_directories.iterator(chunk_size=2000)
    progress = LoopProgress(resource_count, logger)
    map_count = 0

    for directory in progress.iter(resource_iterator):
        map_count += _match_purldb_resources_post_process(
            directory, to_extract_directories, to_resources
        )

    logger(f"{map_count:,d} resource matching refined")


def _match_purldb_resources_post_process(
    directory_path, to_extract_directories, to_resources
):
    # Skip, if the extract directory contains nested archive.
    nested_archive = to_extract_directories.filter(
        path__regex=rf"^{directory_path}.*-extract$"
    ).count()

    if nested_archive > 0:
        return 0

    interesting_codebase_resources = to_resources.filter(
        path__startswith=directory_path
    ).filter(status=flag.MATCHED_TO_PURLDB_RESOURCE)

    if not interesting_codebase_resources:
        return 0

    first_codebase_resource = interesting_codebase_resources.first()
    common_discovered_packages = first_codebase_resource.discovered_packages.all()

    for resource in interesting_codebase_resources[1:]:
        common_discovered_packages = common_discovered_packages.filter(
            id__in=resource.discovered_packages.values_list("id", flat=True)
        )

    common_discovered_packages = list(common_discovered_packages)

    if not common_discovered_packages:
        return 0

    for resource in interesting_codebase_resources:
        resource.discovered_packages.clear()

    for package in common_discovered_packages:
        package.add_resources(list(interesting_codebase_resources))

    # TODO: remove this debug status
    interesting_codebase_resources.update(status="matched-to-purldb-resource-pp")
    return interesting_codebase_resources.count()
