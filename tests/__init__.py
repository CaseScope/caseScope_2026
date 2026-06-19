"""CaseScope unittest package bootstrap."""

from tests._support.isolation import (
    install_discovery_sys_modules_isolation,
    install_unittest_sys_modules_isolation,
)
from tests._support.stubs import install_dependency_stubs


install_dependency_stubs()
install_discovery_sys_modules_isolation()
install_unittest_sys_modules_isolation()
