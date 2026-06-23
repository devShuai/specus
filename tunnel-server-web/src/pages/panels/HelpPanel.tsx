import { useState } from "react";
import { Button, Card, CardBody, CardHeader, Tab, Tabs } from "@heroui/react";
import { notify } from "../../components/toast";

/**
 * 静态帮助文档面板。内置三大客户端启动说明、配置示例、常见问题。
 *
 * <p>文档放在源码里——前端打包时随 SPA 一起发布，无需后端额外接口；管理员升级客户端协议时
 * 修改这个文件即可。代码块支持一键复制。
 */
export function HelpPanel() {
  return (
    <div className="mt-4 flex flex-col gap-4">
      <div>
        <h2 className="text-lg font-semibold">帮助文档</h2>
        <p className="text-small text-default-500">客户端启动方法、配置模板与常见问题</p>
      </div>

      <Tabs aria-label="帮助文档" variant="underlined">
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
          进入「客户端」面板「新建客户端」，系统会自动生成一个客户端 ID。然后到「客户端凭证」面板为该客户端
          签发 API Key + Secret。Secret 仅展示一次，复制保存到客户端配置文件。
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
        <CodeBlock language="bash" code={`cd tunnel-client
mvn org.springframework.boot:spring-boot-maven-plugin:run`} />
      </DocCard>

      <DocCard title="端口冲突">
        <p>
          客户端自带 Spring Boot Web 默认占用 <Inline>8088</Inline>，与服务端管理端口相同。
          单机联调时需要覆盖：
        </p>
        <CodeBlock language="bash" code={`java -jar tunnel-client.jar --server.port=8089`} />
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
      </DocCard>

      <DocCard title="启动命令">
        <p className="mb-2 text-small">需要 .NET Runtime 时：</p>
        <CodeBlock language="bash" code={`dotnet ShuaiTunnel.Client.dll`} />
        <p className="mb-2 mt-3 text-small">自包含可执行包：</p>
        <CodeBlock language="bash" code={`./ShuaiTunnel.Client`} />
        <p className="mb-2 mt-3 text-small">从源码运行：</p>
        <CodeBlock language="bash" code={`cd tunnel-client-csharp
dotnet run --project src/ShuaiTunnel.Client`} />
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
        </ul>
      </DocCard>

      <DocCard title="协议">
        <p className="text-small">
          控制连接走自定义二进制协议，默认 11 字节头（magic / version / serializer / command / length），
          消息体采用紧凑二进制序列化，必要时启用 deflate 压缩。客户端实现之间字节级兼容。
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
          <li>检查 <Inline>remoteAddress</Inline> 和 <Inline>remotePort</Inline> 与服务端控制端口 7010 一致</li>
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
          客户端凭证可以配置 <Inline>maxOnlineInstances</Inline>（默认 2）允许同一凭证同时多实例在线。
          每个实例需要不同 <Inline>clientSessionId</Inline>（登录时自动协商）。
        </p>
      </DocCard>
    </div>
  );
}

// ---- 通用 UI 部件 ----

function DocCard({ title, children }: { title: string; children: React.ReactNode }) {
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
  "clientName": "Demo client",
  "apiKey": "ck_xxxxxxxxxxxxxxxx",
  "secret": "your-client-secret",
  "remoteAddress": "your.server.example.com",
  "remotePort": 7010,
  "tunnelConfigList": [
    {
      "port": 9000,
      "tunnelAddress": "127.0.0.1",
      "tunnelPort": 8080
    }
  ],
  "httpTunnelConfigList": [
    {
      "route": "web",
      "targetBaseUrl": "http://127.0.0.1:8080"
    }
  ]
}`;
