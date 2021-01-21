<?php
namespace SakuraPanel;

use SakuraPanel;

// API 密码，需要和 Frps.ini 里面设置的一样
define("API_TOKEN", "EmptyDream-World-Rcraft-SakuraFrpToken");
define("ROOT", realpath(__DIR__ . "/../"));

if(ROOT === false) {
	exit("Please place this file on /api/ folder");
}

include(ROOT . "/configuration.php");
include(ROOT . "/core/Database.php");
include(ROOT . "/core/Regex.php");
include(ROOT . "/core/Utils.php");

$conn = null;
$db = new SakuraPanel\Database();

include(ROOT . "/core/UserManager.php");
include(ROOT . "/core/NodeManager.php");
include(ROOT . "/core/ProxyManager.php");

$pm = new ProxyManager();
$nm = new NodeManager();

// 服务端 API 部分
// 先进行 Frps 鉴权
if((isset($_GET['apitoken']) && $_GET['apitoken'] == API_TOKEN) || (isset($_GET['action']) && $_GET['action'] == "getconf")) {
	switch($_GET['action']) {
		case "getconf":
			// 精简了一下，用户名可以不用了
			if(isset($_GET['token'], $_GET['node'])) {
				if(Regex::isLetter($_GET['token']) && Regex::isNumber($_GET['node'])) {
					$rs = Database::querySingleLine("tokens", [
						"token" => $_GET['token']
					]);
					if($rs && $nm->isNodeExist($_GET['node'])) {
						$rs = $pm->getUserProxiesConfig($rs['username'], $_GET['node']);
						if(is_string($rs)) {
							Header("Content-Type: text/plain");
							exit($rs);
						} else {
							Utils::sendServerNotFound("Error:User or node not found.[错误]用户未找到，请检查您的配置文件中秘钥是否填写正确！");
						}
					} else {
						Utils::sendServerNotFound("Error:User or node not found.[错误]用户未找到，请检查您的配置文件中秘钥是否填写正确！");
					}
				} else {
					Utils::sendServerNotFound("Error:Invalid token.[错误]非法的token");
				}
			} else {
				Utils::sendServerNotFound("Error:Invalid request.[错误]请求错误");
			}
			break;
		
		// 检查客户端是否合法
		case "checktoken":
			if(isset($_GET['user'])) {
				if(Regex::isLetter($_GET['user']) && strlen($_GET['user']) == 16) {
					$userToken = Database::escape($_GET['user']);
					$rs = Database::querySingleLine("tokens", ["token" => $userToken]);
					if($rs) {
						Utils::sendLoginSuccessful("Message:Login successful, welcome![信息]登录成功，欢迎！");
					} else {
						Utils::sendServerForbidden("Error:Login failed.[错误]登录失败");
					}
				} else {
					Utils::sendServerForbidden("Error:Invalid username.[错误]非法的用户名，请检查配置文件是否有误！");
				}
			} else {
				Utils::sendServerForbidden("Error:Username cannot be empty.[错误]用户名不能为空");
			}
			break;
		
		// 检查隧道是否合法
		case "checkproxy":
			if(isset($_GET['user'])) {
				if(Regex::isLetter($_GET['user']) && strlen($_GET['user']) == 16) {
					$proxyName  = str_replace("{$_GET['user']}.", "", $_GET['proxy_name']);
					$proxyType  = $_GET['proxy_type'] ?? "tcp";
					$remotePort = Intval($_GET['remote_port']) ?? "";
					$userToken  = Database::escape($_GET['user']);
					$rs         = Database::querySingleLine("tokens", ["token" => $userToken]);
					if($rs) {
						if($proxyType == "tcp" || $proxyType == "udp" || $proxyType == "stcp" || $proxyType == "xtcp") {
							if(isset($remotePort) && Regex::isNumber($remotePort)) {
								$username = Database::escape($rs['username']);
								// 这里只对远程端口做限制，可根据自己的需要修改
								$rs = Database::querySingleLine("proxies", [
									"username"    => $username,
									"remote_port" => $remotePort,
									"proxy_type"  => $proxyType
								]);
								if($rs) {
									if($rs['status'] !== "0") {
										Utils::sendServerForbidden("Error:Proxy disabled.[错误]隧道已被禁用");
									}
									Utils::sendCheckSuccessful("Message:Proxy exist[信息]隧道状态正常");
								} else {
									//报错来源
									//暂时性修复(By晓空)
									//请注意，这样是不安全的，因为会对xtcp和stcp隧道进行近乎无限制的放行
									if($proxyType == "stcp" || $proxyType == "xtcp")
									{
										Utils::sendCheckSuccessful("Message:Proxy exist[信息]隧道状态正常");
										//Utils::sendServerNotFound("Proxy not found");
									}
									else
									{
										Utils::sendServerNotFound("Error:Proxy not found.[错误]隧道未找到");
									}
								}
							} else {
								Utils::sendServerBadRequest("Error:Invalid request[错误]请求错误");
							}
						} elseif($proxyType == "http" || $proxyType == "https") {
							if(isset($_GET['domain']) || isset($_GET['subdomain'])) {
								// 目前只验证域名和子域名
								$domain    = $_GET['domain'] ?? "null";
								$subdomain = $_GET['subdomain'] ?? "null";
								$username  = $rs['username'];
								$domain    = $domain;
								$subdomain = $subdomain;
								$domainSQL = (isset($_GET['domain']) && !empty($_GET['domain'])) ? ["domain" => $domain] : ["subdomain" => $subdomain];
								$querySQL  = [
									"username"   => $username,
									"proxy_type" => $proxyType
								];
								$querySQL  = Array_merge($querySQL, $domainSQL);
								$rs        = Database::querySingleLine("proxies", $querySQL);
								if($rs) {
									if($rs['status'] !== "0") {
										Utils::sendServerForbidden("Error:Proxy disabled.[错误]隧道已被禁用");
									}
									Utils::sendCheckSuccessful("Proxy exist");
								} else {
									Utils::sendServerNotFound("Error:Proxy not found.[错误]隧道未找到");
								}
							} else {
								Utils::sendServerBadRequest("Error:Invalid request.[错误]请求出错");
							}
						} else {
							Utils::sendServerBadRequest("Error:Invalid request.[错误]请求出错");
						}
					} else {
						Utils::sendServerNotFound("Error:User not found.[错误]用户未找到");
					}
				} else {
					Utils::sendServerBadRequest("Error:Invalid request.[错误请求出错]");
				}
			} else {
				Utils::sendServerForbidden("Error:Invalid username.[错误]非法的用户名");
			}
			break;
		case "getlimit":
			if(isset($_GET['user'])) {
				if(Regex::isLetter($_GET['user']) && strlen($_GET['user']) == 16) {
					$userToken = Database::escape($_GET['user']);
					$rs = Database::querySingleLine("tokens", ["token" => $userToken]);
					if($rs) {
						$username = Database::escape($rs['username']);
						$ls       = Database::querySingleLine("limits", ["username" => $username]);
						if($ls) {
							Utils::sendJson(Array(
								'status' => 200,
								'max-in' => Floatval($ls['inbound']),
								'max-out' => Floatval($ls['outbound'])
							));
						} else {
							$uinfo = Database::querySingleLine("users", ["username" => $username]);
							if($uinfo) {
								if($uinfo['group'] == "admin") {
									Utils::sendJson(Array(
										'status' => 200,
										'max-in' => 1000000,
										'max-out' => 1000000
									));
								}
								$group = Database::escape($uinfo['group']);
								$gs    = Database::querySingleLine("groups", ["name" => $group]);
								if($gs) {
									Utils::sendJson(Array(
										'status' => 200,
										'max-in' => Floatval($gs['inbound']),
										'max-out' => Floatval($gs['outbound'])
									));
								} else {
									Utils::sendJson(Array(
										'status' => 200,
										'max-in' => 1024,
										'max-out' => 1024
									));
								}
							} else {
								Utils::sendServerForbidden("Error:User not exist.[错误]用户未找到");
							}
						}
					} else {
						Utils::sendServerForbidden("Error:Login failed.[错误]登录失败");
					}
				} else {
					Utils::sendServerForbidden("Error:Invalid username.[错误]非法的用户名");
				}
			} else {
				Utils::sendServerForbidden("Error:Username cannot be empty.[错误]用户名不能为空");
			}
			break;
		default:
			Utils::sendServerNotFound("Error:Undefined action.[错误]未被定义的行为");
	}
} else {
	Utils::sendServerNotFound("Error:Invalid request.[错误]请求出错");
}
