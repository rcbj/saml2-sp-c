# The recipe for building this library from a checkout, so a clone of a release tag
# goes into the local Conan cache:
#
#   conan create . --build=missing
#
# It builds from the files in this tree, never from a download. conan/ holds the
# ConanCenter-layout recipe, which builds from the GitHub release archive instead;
# both run conan/all/test_package/.
import os

from conan import ConanFile
from conan.errors import ConanException, ConanInvalidConfiguration
from conan.tools.build import check_min_cppstd, stdcpp_library
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import copy, load, rmdir

required_conan_version = ">=2.1"


class IyaSaml2SpConan(ConanFile):
    name = "iya-saml2-sp"
    description = "Server-side SAML 2.0 service provider for C and C++, with a CAEP and RISC Shared Signals receiver"
    license = "MIT"
    url = "https://github.com/rcbj/saml2-sp-c"
    homepage = "https://github.com/rcbj/saml2-sp-c"
    topics = ('saml', 'saml2', 'sso', 'caep', 'risc', 'shared-signals')
    package_type = "library"
    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
    }
    implements = ["auto_shared_fpic"]
    exports_sources = "CMakeLists.txt", "VERSION", "LICENSE", "cmake/*", "include/*", "src/*"
    test_package_folder = "conan/all/test_package"

    def set_version(self):
        # VERSION is the one version: the CMake project, the release tag and this package.
        # Conan calls this even when --version is given (self.version is then already set);
        # a --version that is not VERSION's would label this tree as another release.
        version = load(self, os.path.join(self.recipe_folder, "VERSION")).strip()
        if self.version and str(self.version) != version:
            raise ConanException(
                f"--version {self.version} is not this checkout's VERSION, {version}")
        self.version = version

    def layout(self):
        cmake_layout(self)

    def requirements(self):
        self.requires("openssl/[>=3 <4]")
        self.requires("libxml2/[>=2.12 <3]")
        self.requires("zlib/[>=1.2.11 <2]")

    def validate(self):
        check_min_cppstd(self, 17)
        # POSIX sockets and threads; the library has not been ported to Windows.
        if self.settings.os == "Windows":
            raise ConanInvalidConfiguration(f"{self.ref} does not support Windows yet")

    def build_requirements(self):
        self.tool_requires("cmake/[>=3.16 <4]")

    def generate(self):
        tc = CMakeToolchain(self)
        tc.cache_variables["IYA_SAML_BUILD_TESTS"] = False
        tc.cache_variables["IYA_SAML_BUILD_PROGRAMS"] = False
        tc.generate()
        CMakeDeps(self).generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        copy(self, "LICENSE", self.source_folder, os.path.join(self.package_folder, "licenses"))
        cmake = CMake(self)
        cmake.install()
        rmdir(self, os.path.join(self.package_folder, "lib", "cmake"))

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "iya_saml")
        self.cpp_info.set_property("cmake_target_name", "iya::saml")
        self.cpp_info.libs = ["iya_saml"]
        if self.settings.os in ["Linux", "FreeBSD"]:
            self.cpp_info.system_libs.append("pthread")
        if not self.options.shared:
            libcxx = stdcpp_library(self)
            if libcxx:
                self.cpp_info.system_libs.append(libcxx)
