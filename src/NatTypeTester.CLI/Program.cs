using Socks5.Models;
using STUN.Client;
using STUN.Proxy;
using System.CommandLine;
using System.CommandLine.Help;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;

namespace NatTypeTester.CLI;

internal class Program
{
	static void Main(string[] args)
	{
		RootCommand cmd = new("NAT type tester");

		Argument<string> serverArg = new("server");
		Option<string> serverOption = new("--server", "-s")
		{
			Description = "which server to use",
		};
		Option<int> portOption = new("--port", "-p")
		{
			Description = "which port to use",
			DefaultValueFactory = (_) => 3478,
		};
		Option<bool> oldModeOption = new("--3489", "-3")
		{
			Description = "use RFC 3489 client",
			DefaultValueFactory = (_) => false,
		};
		Option<bool> ip6Mode = new("--ipv6", "-6")
		{
			Description = "prefer IPv6",
			DefaultValueFactory = (_) => false,
		};
		Option<string> proxyOption = new("--proxy", "-x")
		{
			Description = "proxy address",
		};
		Option<string> proxyUserOption = new("--proxy-user", "-U")
		{
			Description = "proxy user",
		};
		Option<bool> tcpOption = new("--tcp", "-t")
		{
			Description = "use TCP",
		};
		Option<bool> tlsOption = new("--tls", "-l")
		{
			Description = "use TLS",
		};

		cmd.Add(serverArg);
		cmd.Add(serverOption);
		cmd.Add(portOption);
		cmd.Add(oldModeOption);
		cmd.Add(proxyOption);
		cmd.Add(proxyUserOption);
		cmd.Add(tcpOption);
		cmd.Add(tlsOption);
		cmd.Add(ip6Mode);

		cmd.SetAction(async result =>
		{
			string server = result.GetValue(serverOption) ?? result.GetValue(serverArg) ?? "";
			if (string.IsNullOrEmpty(server))
			{
				new HelpAction().Invoke(result);
				Environment.Exit(1);
			}
			string proxy = result.GetValue(proxyOption) ?? "";
			bool preferV6 = result.GetValue(ip6Mode);

			bool tcp = result.GetValue(tcpOption);
			bool tls = result.GetValue(tlsOption);

			DnsEndPoint serverDEP = ParseEndPoint(server, result.GetValue(portOption));
			IPEndPoint serverIEP = Resolve(serverDEP, preferV6);
			IPEndPoint? proxyIEP = null;
			if (!string.IsNullOrEmpty(proxy))
			{
				DnsEndPoint proxyDEP = ParseEndPoint(proxy, 1080);
				proxyIEP = Resolve(proxyDEP, preferV6);
			}
			IPEndPoint firstHop = serverIEP;
			Socks5CreateOption? createOption = null;
			if (proxyIEP != null)
			{
				string user = result.GetValue(proxyUserOption) ?? "";
				string password = "";
				if (!string.IsNullOrEmpty(user))
				{
					string[] sp = user.Split(':', 2);
					user = sp[0];
					if (sp.Length > 1)
					{
						password = sp[1];
					}
					else
					{
						Console.Write("Password:");
						password = ReadPassword();
					}
				}

				firstHop = proxyIEP;
				createOption = new()
				{
					Address = proxyIEP.Address,
					Port = (ushort)proxyIEP.Port,
					UsernamePassword = string.IsNullOrEmpty(user) ? null : new()
					{
						UserName = user,
						Password = password,
					}
				};
			}
			IPAddress localAny = firstHop.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any;
			IPEndPoint localEP = new(localAny, 0);
			if (tcp)
			{
				ITcpProxy? tcpProxy = null;
				if (tls)
				{
					if (proxyIEP != null)
					{
						tcpProxy = new TlsOverSocks5Proxy(createOption!, serverDEP.Host);
					}
					else
					{
						tcpProxy = new TlsProxy(serverDEP.Host);
					}
				}
				StunClient5389TCP c5t = new(serverIEP, localEP, tcpProxy);
				await c5t.QueryAsync();
				Console.WriteLine(c5t.State);
				return;
			}

			IUdpProxy? udpProxy = null;
			if (proxyIEP != null)
			{
				udpProxy = new Socks5UdpProxy(localEP, createOption!);
			}
			if (result.GetValue(oldModeOption))
			{
				StunClient3489 c3 = new(serverIEP, localEP, udpProxy);
				await c3.ConnectProxyAsync();
				await c3.QueryAsync();
				await c3.CloseProxyAsync();
				Console.WriteLine(c3.State);
				return;
			}

			StunClient5389UDP c5u = new(serverIEP, localEP, udpProxy);
			await c5u.ConnectProxyAsync();
			await c5u.QueryAsync();
			await c5u.CloseProxyAsync();
			Console.WriteLine(c5u.State);
		});

		ParseResult result = cmd.Parse(args);
		result.Invoke();
	}

	static DnsEndPoint ParseEndPoint(string host, int port = -1)
	{
		string pattern = @"^(.+):(\d*)$";
		Regex re = new(pattern, RegexOptions.Compiled);
		Match result = re.Match(host);
		if (result.Success)
		{
			host = result.Groups[1].Value;
			string portStr = result.Groups[2].Value;
			port = int.Parse(portStr);
		}
		else
		{
			if (port < 0)
			{
				throw new ArgumentException(null, nameof(port));
			}
		}
		return new DnsEndPoint(host, port);
	}

	static IPEndPoint Resolve(DnsEndPoint endPoint, bool preferV6)
	{
		IPAddress? v6 = null;
		IPAddress? v4 = null;
		foreach (IPAddress addr in Dns.GetHostAddresses(endPoint.Host))
		{
			switch (addr.AddressFamily)
			{
				case AddressFamily.InterNetwork:
					v4 ??= addr;
					continue;
				case AddressFamily.InterNetworkV6:
					v6 ??= addr;
					continue;
				default:
					continue;
			}
		}

		IPAddress? ip = v4 ?? v6;
		if (preferV6)
		{
			ip = v6 ?? v4;
		}
		if (ip == null)
		{
			Console.WriteLine("can't resolve address");
			Environment.Exit(1);
		}

		return new IPEndPoint(ip, endPoint.Port);
	}

	static string ReadPassword()
	{
		StringBuilder sb = new();
		ConsoleKeyInfo key;
		while ((key = Console.ReadKey(true)).Key != ConsoleKey.Enter)
		{
			if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
			{
				sb.Remove(sb.Length - 1, 1);
			}
			else if (!char.IsControl(key.KeyChar))
			{
				sb.Append(key.KeyChar);
			}
		}
		Console.Write(Environment.NewLine);
		return sb.ToString();
	}
}
