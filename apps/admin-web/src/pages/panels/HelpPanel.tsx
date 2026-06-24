import { useEffect, useState } from "react";
import { Button, Card, CardBody, CardHeader, Chip, Tab, Tabs } from "@heroui/react";
import { notify } from "../../components/toast";
import { NAT_TRAVERSAL_REFERENCE, NAT_TYPE_PROFILES } from "../../lib/nat";

const HELP_TABS = [
  "quickstart",
  "java",
  "go",
  "csharp",
  "peer-mesh",
  "protocol",
  "faq",
] as const;
type HelpTabKey = (typeof HELP_TABS)[number];
const HELP_TAB_SET = new Set<HelpTabKey>(HELP_TABS);

export const HELP_NAT_TYPES_ANCHOR = "nat-types";

function readHelpTabFromLocation(): HelpTabKey {
  // hash 形如 #/help/peer-mesh 或 #/help/peer-mesh#nat-types
  const raw = window.location.hash.replace(/^#\/?/, "");
  const segments = raw.split(/[?#]/, 1)[0].split("/");
  const candidate = segments[1] ?? "";
  return HELP_TAB_SET.has(candidate as HelpTabKey) ? (candidate as HelpTabKey) : "quickstart";
}

/**
 * 静态帮助文档面板。内置三大客户端启动说明、配置示例、常见问题。
 *
 * <p>文档放在源码里——前端打包时随 SPA 一起发布，无需后端额外接口；管理员升级客户端协议时
 * 修改这个文件即可。代码块支持一键复制。
 */
export function HelpPanel() {
  const [activeTab, setActiveTab] = useState<HelpTabKey>(() => readHelpTabFromLocation());

  useEffect(() => {
    const sync = () => {
      setActiveTab(readHelpTabFromLocation());
      // 处理 hash 中的二级锚点 #/help/peer-mesh#nat-types
      const sub = window.location.hash.split("#")[2];
      if (sub) {
        setTimeout(() => {
          document.getElementById(sub)?.scrollIntoView({ behavior: "smooth", block: "start" });
        }, 80);
      }
    };
    sync();
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);

  const onTabChange = (key: string | number) => {
    const next = (typeof key === "string" ? key : String(key)) as HelpTabKey;
    if (!HELP_TAB_SET.has(next)) {
      return;
    }
    setActiveTab(next);
    if (window.location.hash !== `#/help/${next}`) {
      window.location.hash = `/help/${next}`;
    }
  };

  return (
    <div className="mt-4 flex flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold">帮助文档</h2>
        <p className="text-small text-default-500">客户端启动方法、配置模板与常见问题</p>
      </div>

      <Tabs aria-label="帮助文档" variant="underlined" selectedKey={activeTab} onSelectionChange={onTabChange}>
        <Tab key="quickstart" title="快速开始">
          <QuickStartSection />
        </Tab>
        <Tab key="java" title="Java 客户端">
          <JavaSection />
        </Tab>
        <Tab key="go" title="Go 客户端">
          <GoSection />
        </Tab>
        <Tab key="csharp" title=".NET 客户端">
          <CsharpSection />
        </Tab>
        <Tab key="peer-mesh" title="私有组网">
          <PeerMeshSection />
        </Tab>
        <Tab key="protocol" title="协议与端口">
          <ProtocolSection />
        </Tab>
        <Tab key="faq" title="常见问题">
          <FaqSection />
        </Tab>
      </Tabs>
    </div>
  );
}

function QuickStartSection() {
  return (
    <div className="mt-4 flex flex-col gap-4">
      <DocCard title="1. 登录管理后台">
        <p>
          默认账号 <Inline>admin / admin</Inline>，部署前请务必在「系统管理 → 用户管理」修改密码或添加新用户。
          支持本地用户名密码登录与 OIDC 单点登录，二者可同时启用。
        </p>
      </DocCard>

      <DocCard title="2. 创建客户端账号">
        <p>
          进入「客户端」面板「新建客户端」，系统会自动生成客户端和启动凭证。API Key + Secret 用于客户端启动时
          调用 HTTP 登录接口。Secret 仅展示一次，复制保存到客户端配置文件。
        </p>
      </DocCard>

      <DocCard title="3. 配置端口映射 / HTTP 路由">
        <ul className="ml-5 list-disc space-y-1">
          <li>
            <b>端口映射</b>：把公网 TCP 端口（如 9000）转发到客户端内网的目标地址端口（如 127.0.0.1:8080）。
          </li>
          <li>
            <b>HTTP 路由</b>：通过 <Inline>https://server/http/&#123;clientName&#125;/&#123;route&#125;/...</Inline> 转发到客户端内网的 HTTP 服务，
            支持路径改写（让内网应用绝对路径可以正常工作）。
          </li>
        </ul>
      </DocCard>

      <DocCard title="4. 下载并启动客户端">
        <p>
          打开「客户端下载」面板获取对应实现的客户端，按下面各 Tab 的说明启动。所有实现共享同一份 JSON 配置格式。
          端口映射、HTTP 路由和私有组网配置都由服务端登录响应下发。
        </p>
      </DocCard>
    </div>
  );
}

function JavaSection() {
  return (
    <div className="mt-4 flex flex-col gap-4">
      <DocCard title="环境要求">
        <p>JDK 21 或更高版本。</p>
      </DocCard>

      <DocCard title="配置文件 tunnelClientConfig.json">
        <p className="mb-2 text-small">放在与 jar 同目录或工作目录下：</p>
        <CodeBlock language="json" code={SAMPLE_CONFIG} />
      </DocCard>

      <DocCard title="启动命令">
        <p className="mb-2 text-small">从可执行 jar 启动：</p>
        <CodeBlock language="bash" code={`java -jar tunnel-client.jar`} />
        <p className="mb-2 mt-3 text-small">从源码启动：</p>
        <CodeBlock language="bash" code={`cd implementations/java/client
mvn org.springframework.boot:spring-boot-maven-plugin:run`} />
      </DocCard>

      <DocCard title="配置来源">
        <p>
          Java 客户端当前不启动 Web 服务，本地配置只保存启动登录信息。客户端启动后会先调用
          <Inline>/api/client/auth/login</Inline> 获取控制连接地址、访问令牌、端口映射、HTTP 路由和 peer mesh 配置。
        </p>
      </DocCard>
    </div>
  );
}

function GoSection() {
  return (
    <div className="mt-4 flex flex-col gap-4">
      <DocCard title="环境要求">
        <p>无需额外运行时，单二进制部署。各操作系统/架构有独立产物。</p>
      </DocCard>

      <DocCard title="配置文件">
        <p className="mb-2 text-small">放在二进制同目录或工作目录下：</p>
        <CodeBlock language="json" code={SAMPLE_CONFIG} />
        <p className="mt-2 text-small text-default-500">
          非 Java 客户端需要与当前 Java 协议保持一致：启动配置只包含 HTTP 登录凭证，端口映射和 HTTP 路由由服务端下发。
        </p>
      </DocCard>

      <DocCard title="启动命令">
        <p className="mb-2 text-small">Linux / macOS：</p>
        <CodeBlock language="bash" code={`chmod +x shuai-tunnel-client
./shuai-tunnel-client`} />
        <p className="mb-2 mt-3 text-small">Windows：</p>
        <CodeBlock language="powershell" code={`.\\shuai-tunnel-client.exe`} />
      </DocCard>

      <DocCard title="后台运行">
        <p>建议使用 systemd / Windows Service 托管。或简单后台运行：</p>
        <CodeBlock language="bash" code={`nohup ./shuai-tunnel-client > tunnel-client.log 2>&1 &`} />
      </DocCard>
    </div>
  );
}

function CsharpSection() {
  return (
    <div className="mt-4 flex flex-col gap-4">
      <DocCard title="环境要求">
        <p>
          .NET 10 Runtime（或使用自包含发布版本，无需安装 .NET）。
        </p>
      </DocCard>

      <DocCard title="配置文件">
        <p className="mb-2 text-small">放在程序集所在目录或工作目录下：</p>
        <CodeBlock language="json" code={SAMPLE_CONFIG} />
        <p className="mt-2 text-small text-default-500">
          非 Java 客户端需要与当前 Java 协议保持一致：启动配置只包含 HTTP 登录凭证，端口映射和 HTTP 路由由服务端下发。
        </p>
      </DocCard>

      <DocCard title="启动命令">
        <p className="mb-2 text-small">需要 .NET Runtime 时：</p>
        <CodeBlock language="bash" code={`dotnet ShuaiTunnel.Client.dll`} />
        <p className="mb-2 mt-3 text-small">自包含可执行包：</p>
        <CodeBlock language="bash" code={`./ShuaiTunnel.Client`} />
        <p className="mb-2 mt-3 text-small">从源码运行：</p>
        <CodeBlock language="bash" code={`cd implementations/csharp/client
dotnet run --project src/ShuaiTunnel.Client`} />
      </DocCard>
    </div>
  );
}

function PeerMeshSection() {
  return (
    <div className="mt-4 flex flex-col gap-4">
      <DocCard title="启用条件">
        <ul className="ml-5 list-disc space-y-1 text-small">
          <li>
            服务端设置 <Inline>TUNNEL_PEER_MESH_ENABLED=true</Inline>。
          </li>
          <li>
            在「私有组网」页面启用对应客户端。默认同一租户 / 同一用户下客户端可互访；跨用户需要显式 ACL。
          </li>
          <li>
            客户端启动配置可选择 <Inline>peerMeshDevice</Inline>：默认 <Inline>noop</Inline> 只做探测和加密 UDP 数据面，
            <Inline>auto</Inline>、<Inline>linux-tun</Inline>、<Inline>windows-wintun</Inline> 会尝试创建虚拟网卡。
          </li>
        </ul>
      </DocCard>

      <DocCard title="客户端配置示例">
        <CodeBlock language="json" code={PEER_MESH_CONFIG} />
      </DocCard>

      <DocCard title="UDP 端口">
        <ul className="ml-5 list-disc space-y-1 text-small">
          <li>
            <Inline>3478/udp</Inline>：内置 STUN/TURN-lite 主端口，承载 binding、relay allocation 和 relay 数据。
          </li>
          <li>
            <Inline>3479/udp</Inline>：NAT 类型辅助探测端口。默认由
            <Inline>TUNNEL_PEER_MESH_STUN_TURN_PORT + 1</Inline> 得到，可用
            <Inline>TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT</Inline> 显式覆盖。
          </li>
        </ul>
        <CodeBlock language="bash" code={`sudo firewall-cmd --add-port=3478/udp --permanent
sudo firewall-cmd --add-port=3479/udp --permanent
sudo firewall-cmd --reload`} />
      </DocCard>

      <DocCard title="检测链路">
        <p className="mb-2 text-small text-default-500">
          客户端使用 UDP 主端口和辅助端口判断公网映射行为。四步组成一次完整的 NAT 类型探测：
        </p>
        <div className="grid gap-2">
          {[
            ["1", "Binding", "客户端向 STUN/TURN-lite 主端口发送探测包。"],
            ["2", "Mapped Endpoint", "服务端记录公网 IP:Port 并回传。"],
            ["3", "Alternate Port", "向辅助 UDP 端口探测，比较映射是否变化。"],
            ["4", "Path Policy", "直连友好优先 direct，Symmetric NAT 快速 relay。"],
          ].map(([index, title, text]) => (
            <div
              key={index}
              className="grid grid-cols-[32px_minmax(0,1fr)] gap-3 rounded-md border border-default-200 bg-default-50 p-2 dark:bg-default-100/10"
            >
              <span className="flex h-8 w-8 items-center justify-center rounded bg-primary-100 font-mono text-small text-primary">
                {index}
              </span>
              <span className="min-w-0">
                <span className="block font-semibold text-foreground">{title}</span>
                <span className="text-small text-default-500">{text}</span>
              </span>
            </div>
          ))}
        </div>
      </DocCard>

      <DocCard title={<span id={HELP_NAT_TYPES_ANCHOR}>NAT 类型速查</span>}>
        <p className="mb-2 text-small text-default-500">
          下表用于解释「私有组网」面板里客户端 NAT 探测结果和路径建议。
        </p>
        <div className="grid gap-2 md:grid-cols-2">
          {Object.values(NAT_TYPE_PROFILES).map((profile) => (
            <div
              key={profile.key}
              className="rounded-md border border-default-200 bg-default-50 p-3 dark:bg-default-100/10"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-small font-semibold">{profile.label}</span>
                <Chip size="sm" color={profile.tone} variant="flat">
                  {profile.reachabilityLabel}
                </Chip>
              </div>
              <p className="mt-1 text-tiny leading-5 text-default-500">{profile.summary}</p>
              <p className="mt-1 text-tiny leading-5 text-default-400">
                <span className="text-default-500">建议：</span>
                {profile.recommendation}
              </p>
            </div>
          ))}
        </div>
        <p className="mt-3 text-tiny text-default-500">
          只有一个公网 IP 时，不能严格拆分 Full Cone 与 Address-Restricted NAT，所以页面合并展示。
        </p>
      </DocCard>

      <DocCard title="NAT 穿透说明">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <p className="text-small text-default-500">根据 Tailscale NAT traversal 文章做中文改写。</p>
          <Button
            as="a"
            href={NAT_TRAVERSAL_REFERENCE.url}
            rel="noreferrer"
            target="_blank"
            size="sm"
            variant="flat"
          >
            阅读原文
          </Button>
        </div>
        <div className="grid gap-2 md:grid-cols-2">
          {NAT_TRAVERSAL_REFERENCE.notes.map((note) => (
            <div
              key={note.title}
              className="rounded-md border border-default-200 bg-default-50 p-3 dark:bg-default-100/10"
            >
              <div className="text-small font-semibold text-foreground">{note.title}</div>
              <p className="mt-1 text-small leading-6 text-default-500">{note.text}</p>
            </div>
          ))}
        </div>
      </DocCard>

      <DocCard title="虚拟网卡要求">
        <ul className="ml-5 list-disc space-y-1 text-small">
          <li>Linux：需要 root 或 <Inline>CAP_NET_ADMIN</Inline>，系统需要 <Inline>/dev/net/tun</Inline>。</li>
          <li>Windows：需要管理员权限。客户端已内置 Wintun DLL，会优先从程序资源释放到本地后加载。</li>
          <li>失败时客户端会回退 <Inline>noop</Inline> 并把虚拟网卡状态上报到「私有组网」页面。</li>
        </ul>
      </DocCard>
    </div>
  );
}

function ProtocolSection() {
  return (
    <div className="mt-4 flex flex-col gap-4">
      <DocCard title="端口规划">
        <ul className="ml-5 list-disc space-y-1 text-small">
          <li>
            <Inline>7010</Inline> — 控制连接端口，客户端连接此端口完成登录、心跳、隧道管理。
            通过环境变量 <Inline>TUNNEL_NETTY_PORT</Inline> 覆盖。
          </li>
          <li>
            <Inline>8088</Inline> — 管理后台 + HTTP 直转入口。
            <Inline>/http/&#123;client&#125;/&#123;route&#125;/...</Inline> 为公开流量入口。
          </li>
          <li>各「端口映射」自定义的公网监听端口（如 9000）。</li>
          <li>
            <Inline>3478/udp</Inline> — peer mesh STUN/TURN-lite 主端口。
            通过环境变量 <Inline>TUNNEL_PEER_MESH_STUN_TURN_PORT</Inline> 覆盖。
          </li>
          <li>
            <Inline>3479/udp</Inline> — peer mesh NAT 类型辅助探测端口，默认是主端口 + 1。
            通过环境变量 <Inline>TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT</Inline> 覆盖。
          </li>
        </ul>
      </DocCard>

      <DocCard title="协议">
        <p className="text-small">
          控制连接走自定义二进制协议，默认 11 字节头（magic / version / serializer / command / length），
          消息体采用紧凑二进制序列化，必要时启用 deflate 压缩。客户端实现之间字节级兼容。
          Peer mesh 信令复用控制连接的 <Inline>PEER_CONTROL</Inline>，数据面优先 UDP 直连，失败后走内置 TURN-lite relay。
        </p>
      </DocCard>

      <DocCard title="控制连接 TLS">
        <p className="text-small">通过 <Inline>TUNNEL_TLS_MODE</Inline> 环境变量切换：</p>
        <ul className="ml-5 list-disc space-y-1 text-small">
          <li>
            <Inline>disabled</Inline>（默认）—— 明文 TCP，与旧部署兼容
          </li>
          <li>
            <Inline>file</Inline> —— 从磁盘加载 keystore（生产用）
          </li>
          <li>
            <Inline>self-signed</Inline> —— 启动时生成一次性自签名证书（开发/测试用）
          </li>
        </ul>
      </DocCard>
    </div>
  );
}

function FaqSection() {
  return (
    <div className="mt-4 flex flex-col gap-4">
      <DocCard title="客户端显示「客户端不在线」">
        <ul className="ml-5 list-disc space-y-1 text-small">
          <li>检查 <Inline>serverBaseUrl</Inline> 是否能访问服务端管理 HTTP 地址</li>
          <li>检查服务端登录响应里的控制连接地址和端口是否可达，默认控制端口为 7010</li>
          <li>检查防火墙是否放行 7010</li>
          <li>检查客户端日志：登录失败一般是 API Key / Secret 不对，或 Secret 包含尾随空白字符</li>
          <li>服务端 TLS 启用后，客户端必须同步启用 TLS 才能握手</li>
        </ul>
      </DocCard>

      <DocCard title="HTTP 直转访问内网应用路径丢失">
        <p className="text-small">
          内网应用返回的 HTML/CSS 中包含绝对路径（如 <Inline>/assets/x.js</Inline>），公网访问时会指向根路径而非隧道前缀。
          解决方案：进入「HTTP 路由」编辑目标路由，开启「路径改写」开关。
          服务端会自动改写 HTML/CSS，并向 HTML 注入运行时 polyfill 拦截 fetch / XHR / setAttribute 等 API，
          让 SPA 动态拼接的 URL 也走隧道。
        </p>
      </DocCard>

      <DocCard title="内网 HTTPS 自签证书报错">
        <p className="text-small">
          客户端在 HTTP 直转通道访问内网 <Inline>https://</Inline> 服务时，默认信任所有证书并跳过 hostname 校验。
          仅作为隧道客户端，不会影响管理后台与公网 TLS 的安全性。
        </p>
      </DocCard>

      <DocCard title="登录管理后台后频繁掉线">
        <p className="text-small">
          管理后台 JWT 默认 8 小时有效。通过环境变量 <Inline>TUNNEL_AUTH_TOKEN_TTL_SECONDS</Inline>
          调整本地密码登录的令牌时长。
        </p>
      </DocCard>

      <DocCard title="一台机器多个客户端实例">
        <p className="text-small">
          服务端会按用户和机器限制同一台机器上的实例数量，默认同一用户最多 2 个在线实例。
          同一机器重复启动时，服务端会拒绝超过限制的连接；停止旧实例后可重新登录。
        </p>
      </DocCard>

      <DocCard title="私有组网一直显示 NAT 未知">
        <ul className="ml-5 list-disc space-y-1 text-small">
          <li>确认服务端已启用 <Inline>TUNNEL_PEER_MESH_ENABLED=true</Inline>，并且客户端在「私有组网」页面已启用。</li>
          <li>确认 UDP <Inline>3478</Inline> 可达；如果要更细分类 NAT，还需要放行备用 UDP 端口，默认 <Inline>3479</Inline>。</li>
          <li>如果服务器在 NAT 后面，设置 <Inline>TUNNEL_PEER_MESH_PUBLIC_ADDRESS</Inline> 为公网域名或 IP。</li>
          <li>客户端需要升级到支持 <Inline>probeRole</Inline> 和备用端口探测的版本。</li>
        </ul>
      </DocCard>
    </div>
  );
}

// ---- 通用 UI 部件 ----

function DocCard({ title, children }: { title: React.ReactNode; children: React.ReactNode }) {
  return (
    <Card shadow="none" className="rounded-md border border-default-200">
      <CardHeader className="px-5 pb-2 pt-4">
        <h3 className="text-base font-semibold">{title}</h3>
      </CardHeader>
      <CardBody className="px-5 pb-4 pt-1 text-small leading-6">{children}</CardBody>
    </Card>
  );
}

function Inline({ children }: { children: React.ReactNode }) {
  return <code className="rounded bg-default-100 px-1.5 py-0.5 text-tiny">{children}</code>;
}

function CodeBlock({ language, code }: { language: string; code: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard?.writeText(code);
      setCopied(true);
      notify("已复制到剪贴板");
      setTimeout(() => setCopied(false), 1500);
    } catch {
      notify("复制失败", "error");
    }
  };
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-md border border-default-200 bg-default-50 p-3 text-tiny leading-5">
        <code className={`language-${language}`}>{code}</code>
      </pre>
      <Button
        className="absolute right-2 top-2"
        size="sm"
        variant="flat"
        onPress={() => void onCopy()}
      >
        {copied ? "已复制" : "复制"}
      </Button>
    </div>
  );
}

// 共享配置示例（与 README.md "tunnelClientConfig.json" 样例保持一致）
const SAMPLE_CONFIG = `{
  "serverBaseUrl": "https://tunnel.example.com",
  "apiKey": "demo-client",
  "secret": "your-client-secret"
}`;

const PEER_MESH_CONFIG = `{
  "serverBaseUrl": "https://tunnel.example.com",
  "apiKey": "demo-client",
  "secret": "your-client-secret",
  "peerMeshDevice": "auto",
  "peerMeshTunName": "shuai0",
  "peerMeshMtu": 1400
}`;
