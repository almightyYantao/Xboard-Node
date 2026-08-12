package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// 这些路径以前是 const，两套 agent 并存时第二套的 CLI 会去操作第一套：
// list 显示错实例只是误导，service restart / upgrade / uninstall 打错对象是真会出事。
func TestEnvOrFallsBackWhenUnset(t *testing.T) {
	if got := envOr("LB_NODE_TEST_UNSET_KEY", "fallback"); got != "fallback" {
		t.Fatalf("want fallback, got %q", got)
	}
}

func TestEnvOrIgnoresBlank(t *testing.T) {
	t.Setenv("LB_NODE_TEST_BLANK", "   ")
	if got := envOr("LB_NODE_TEST_BLANK", "fallback"); got != "fallback" {
		t.Fatalf("空白值应当被忽略，got %q", got)
	}
}

func TestEnvOrTrims(t *testing.T) {
	t.Setenv("LB_NODE_TEST_VALUE", " /etc/lb-node \n")
	if got := envOr("LB_NODE_TEST_VALUE", "x"); got != "/etc/lb-node" {
		t.Fatalf("want /etc/lb-node, got %q", got)
	}
}

// 默认值必须还是历史值：现网跑着的 xbctl 不带任何环境变量，行为不能变
func TestDefaultsStayBackwardCompatible(t *testing.T) {
	if !strings.HasPrefix(defaultInstallRoot, "/etc/") {
		t.Fatalf("install root 看起来不对: %q", defaultInstallRoot)
	}
	if defaultConfigPath != filepath.Join(defaultInstallRoot, "config.yml") {
		t.Fatalf("config 路径应当由 install root 派生, got %q", defaultConfigPath)
	}
	if defaultMetaPath != filepath.Join(defaultInstallRoot, "install-meta.json") {
		t.Fatalf("meta 路径应当由 install root 派生, got %q", defaultMetaPath)
	}
	if serviceFilePath != filepath.Join("/etc/systemd/system", serviceName) {
		t.Fatalf("unit 文件路径应当由服务名派生, got %q", serviceFilePath)
	}
	// 自称跟着二进制名走，免得 lbctl 打印 "xboard-node status"
	if appName != filepath.Base(defaultBinaryPath) {
		t.Fatalf("appName 应当等于二进制名, got %q", appName)
	}
}
