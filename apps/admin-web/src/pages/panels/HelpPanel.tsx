import { useEffect, useState, type ReactNode } from "react";
import { Button } from "@heroui/react";
import {
  MACOS_CLIENT_START_COMMAND,
  MACOS_HOMEBREW_INSTALL_COMMAND,
  MACOS_HOMEBREW_UPGRADE_COMMAND,
} from "../../lib/macosInstall";
import { NAT_BEHAVIOR_AXES, NAT_TRAVERSAL_REFERENCE } from "../../lib/nat";
import { CLIENT_ONBOARDING_STEPS } from "../../lib/clientOnboarding";
import { useProductMetricsCollecting } from "../../hooks/useProductMetricsCollecting";
import { ProductMetricsDisclosure, ProductMetricsMemberNotice } from "../../components/ProductMetricsDisclosure";
import { PageHeader } from "../../components/PageHeader";
import { Alert, Card, Icon, Section, TableWrap, Tabs, type IconName } from "../../components/ui";
import { CodeCard, Fold, InlineCode, ModelTag } from "./meshSystemParts";

const HELP_TABS = [
  "quickstart",
  "java",
  "go",
  "csharp",
  "peer-mesh",
  "protocol",
  "faq",
  "metrics",
] as const;
type HelpTabKey = (typeof HELP_TABS)[number];
const HELP_TAB_SET = new Set<HelpTabKey>(HELP_TABS);

const HELP_TAB_ITEMS: Array<{ key: HelpTabKey; label: string; icon: IconName }> = [
  { key: "quickstart", label: "快速开始", icon: "play-circle" },
  { key: "java", label: "Java 客户端", icon: "file-text" },
  { key: "go", label: "Go 客户端", icon: "file-text" },
  { key: "csharp", label: ".NET 客户端", icon: "file-text" },
  { key: "peer-mesh", label: "私有组网", icon: "wifi" },
  { key: "protocol", label: "协议与端口", icon: "server" },
  { key: "faq", label: "常见问题", icon: "message" },
  { key: "metrics", label: "产品指标", icon: "bar-chart" },
];

export const HELP_NAT_TYPES_ANCHOR = "nat-types";

const NAT_PATH_GUIDANCE = [
  {
    label: "EIM + EIF",
    path: "直连优先",
    tone: "success",
    detail: "映射稳定且回包限制最少，优先建立 direct，保留 relay 兜底。",
  },
  {
    label: "EIM + ADF",
    path: "直连较友好",
    tone: "primary",
    detail: "双方并行发包通常可以打洞，超时后自动切换 relay。",
  },
  {
    label: "EIM + APDF",
    path: "条件直连",
    tone: "warning",
    detail: "必须向准确 IP:Port 同时打洞，不应长时间等待 direct。",
  },
  {
    label: "ADM / APDM",
    path: "Relay 优先",
    tone: "danger",
    detail: "映射随目标变化，直连端点难复用；并行探测时提前准备 TURN。",
  },
  {
    label: "UNKNOWN / UNSUPPORTED",
    path: "实际验证",
    tone: "default",
    detail: "探测证据不完整时不做强结论，以 ICE 连通性检查选择最终路径。",
  },
] as const;

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
    let rafA = 0;
    let rafB = 0;
    const sync = () => {
      setActiveTab(readHelpTabFromLocation());
      // 处理 hash 中的二级锚点 #/help/peer-mesh#nat-types
      const sub = window.location.hash.split("#")[2];
      if (sub) {
        // 等 React 提交新 Tab 内容、浏览器完成布局后再滚动，避免魔法延时
        cancelAnimationFrame(rafA);
        cancelAnimationFrame(rafB);
        rafA = requestAnimationFrame(() => {
          rafB = requestAnimationFrame(() => {
            document.getElementById(sub)?.scrollIntoView({ behavior: "smooth", block: "start" });
          });
        });
      }
    };
    sync();
    window.addEventListener("hashchange", sync);
    return () => {
      cancelAnimationFrame(rafA);
      cancelAnimationFrame(rafB);
      window.removeEventListener("hashchange", sync);
    };
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

  const activeLabel = HELP_TAB_ITEMS.find((item) => item.key === activeTab)?.label ?? "帮助文档";

  return (
    <div className="ms-page flex min-w-0 flex-col">
      <PageHeader title="帮助文档" description="客户端启动方法、配置模板与常见问题" />

      <Tabs label="帮助文档" value={activeTab} onChange={onTabChange} items={HELP_TAB_ITEMS} />

      <div role="tabpanel" aria-label={activeLabel} className="ms-doc">
        {activeTab === "quickstart" && <QuickStartSection />}
        {activeTab === "java" && <JavaSection />}
        {activeTab === "go" && <GoSection />}
        {activeTab === "csharp" && <CsharpSection />}
        {activeTab === "peer-mesh" && <PeerMeshSection />}
        {activeTab === "protocol" && <ProtocolSection />}
        {activeTab === "faq" && <FaqSection />}
        {activeTab === "metrics" && <ProductMetricsSection />}
      </div>
    </div>
  );
}

/**
 * The full product-metrics disclosure (protocol/spec/product-metrics.md section 3.1) and, while the
 * member's organisation collects, the standing one-line notice.
 */
function ProductMetricsSection() {
  // The help page is part of the signed-in management console.
  const collecting = useProductMetricsCollecting(true);
  return (
    <DocSection
      title={collecting ? "你所在的组织已开启产品指标" : "产品指标（默认关闭）"}
      description={collecting ? undefined : "只有管理员显式开启后才会统计；开启前和关闭期间的事不会被补算。"}
    >
      {collecting ? <ProductMetricsMemberNotice className="mb-3" /> : null}
      <Card className="ms-doc-card">
        <ProductMetricsDisclosure />
      </Card>
    </DocSection>
  );
}

function QuickStartSection() {
  return (
    <DocSection title="五步完成接入" description="按顺序做：先让设备上线，再发布服务。">
      <ol className="ms-steps">
        <DocStep index={1} title="登录管理后台">
          <p>
            生产模板默认关闭本地密码登录，也不提供可用默认密码。推荐配置 OIDC；要用本地登录，先在服务端生成独立强口令和稳定 JWT
            密钥，再显式开启登录开关。本地登录与 OIDC 可同时启用。
          </p>
        </DocStep>
        {CLIENT_ONBOARDING_STEPS.map((step, index) => (
          <DocStep key={step.title} index={index + 2} title={step.title}>
            <p>{step.detail}</p>
            {index === 3 ? (
              <p className="ms-doc-note">端口映射会开放公网 TCP 端口；HTTP 路由可设置访问用户名和密码。创建配置和设备在线都不等于目标应用已经验证成功。</p>
            ) : null}
            <div className="ms-step-actions">
              <Button as="a" href={step.href} size="sm" variant="flat" endContent={<Icon name="arrow-right" size={14} />}>{step.action}</Button>
            </div>
          </DocStep>
        ))}
      </ol>
    </DocSection>
  );
}

function JavaSection() {
  return (
    <>
      <DocSection title="环境要求">
        <p>JDK 21 或更高版本。</p>
      </DocSection>

      <DocSection title="配置文件 client.jsonc" description="放在与 jar 同目录或工作目录下。">
        <CodeCard language="jsonc" title="client.jsonc" code={SAMPLE_CONFIG} />
      </DocSection>

      <DocSection title="启动命令">
        <DocLabel>从可执行 jar 启动</DocLabel>
        <CodeCard language="bash" code={`java -jar specus-client.jar`} />
        <DocLabel>从源码启动</DocLabel>
        <CodeCard language="bash" code={`cd implementations/java/client
mvn org.springframework.boot:spring-boot-maven-plugin:run`} />
      </DocSection>

      <DocSection title="配置来源">
        <p>
          Java 客户端当前不启动 Web 服务，本地配置只保存启动登录信息。客户端启动后会先调用
          <InlineCode>/api/client/auth/login</InlineCode> 获取控制连接地址、访问令牌、端口映射、HTTP 路由和 peer mesh 配置。
        </p>
      </DocSection>
    </>
  );
}

function GoSection() {
  return (
    <>
      <DocSection title="环境要求">
        <p>无需额外运行时，单二进制部署。各操作系统/架构有独立产物。</p>
      </DocSection>

      <DocSection title="macOS 安装（推荐）" description="Homebrew Cask 会自动选择 Apple Silicon 或 Intel 版本。">
        <DocLabel>安装</DocLabel>
        <CodeCard language="bash" code={MACOS_HOMEBREW_INSTALL_COMMAND} />
        <DocLabel>指定配置文件启动</DocLabel>
        <CodeCard language="bash" code={MACOS_CLIENT_START_COMMAND} />
        <DocLabel>升级到最新版本</DocLabel>
        <CodeCard language="bash" code={MACOS_HOMEBREW_UPGRADE_COMMAND} />
      </DocSection>

      <DocSection title="配置文件 client.jsonc" description="放在二进制同目录或工作目录下。">
        <CodeCard language="jsonc" title="client.jsonc" code={SAMPLE_CONFIG} />
        <p className="ms-doc-note">
          非 Java 客户端需要与当前 Java 协议保持一致：启动配置只包含 HTTP 登录凭证，端口映射和 HTTP 路由由服务端下发。
        </p>
      </DocSection>

      <DocSection title="启动命令">
        <DocLabel>Linux / macOS 手动下载包</DocLabel>
        <CodeCard language="bash" code={`chmod +x specus-client
./specus-client -config ./client.jsonc`} />
        <DocLabel>Windows</DocLabel>
        <CodeCard language="powershell" code={`.\\specus-client.exe`} />
      </DocSection>

      <DocSection title="后台运行" description="建议用 systemd / Windows Service 托管；临时也可以这样放到后台。">
        <CodeCard language="bash" code={`nohup ./specus-client > specus-client.log 2>&1 &`} />
      </DocSection>
    </>
  );
}

function CsharpSection() {
  return (
    <>
      <DocSection title="环境要求">
        <p>
          .NET 10 Runtime（或使用自包含发布版本，无需安装 .NET）。
        </p>
      </DocSection>

      <DocSection title="配置文件 client.jsonc" description="放在程序集所在目录或工作目录下。">
        <CodeCard language="jsonc" title="client.jsonc" code={SAMPLE_CONFIG} />
        <p className="ms-doc-note">
          非 Java 客户端需要与当前 Java 协议保持一致：启动配置只包含 HTTP 登录凭证，端口映射和 HTTP 路由由服务端下发。
        </p>
      </DocSection>

      <DocSection title="启动命令">
        <DocLabel>需要 .NET Runtime 时</DocLabel>
        <CodeCard language="bash" code={`dotnet Specus.Client.dll`} />
        <DocLabel>自包含可执行包</DocLabel>
        <CodeCard language="bash" code={`./Specus.Client`} />
        <DocLabel>从源码运行</DocLabel>
        <CodeCard language="bash" code={`cd implementations/csharp/client
dotnet run --project src/Specus.Client`} />
      </DocSection>
    </>
  );
}

function PeerMeshSection() {
  return (
    <>
      <DocSection title="启用条件">
        <ul className="ms-doc-list">
          <li>
            服务端设置 <InlineCode>SPECUS_PEER_MESH_ENABLED=true</InlineCode>。
          </li>
          <li>
            在「私有组网」页面启用对应客户端。默认同一租户 / 同一用户下客户端可互访；跨用户需要显式 ACL。
          </li>
          <li>
            客户端启动配置可选择 <InlineCode>peerMeshDevice</InlineCode>：默认 <InlineCode>noop</InlineCode> 只做探测和加密 UDP 数据面，
            <InlineCode>auto</InlineCode>、<InlineCode>linux-tun</InlineCode>、<InlineCode>windows-wintun</InlineCode> 会尝试创建虚拟网卡。
          </li>
        </ul>
      </DocSection>

      <DocSection title="客户端配置示例">
        <CodeCard language="jsonc" title="client.jsonc" code={PEER_MESH_CONFIG} />
      </DocSection>

      <DocSection title="UDP 端口">
        <ul className="ms-doc-list">
          <li>
            <InlineCode>3478/udp</InlineCode>：specus-server 的认证 TURN 控制端口，承载 allocation、permission 和 relay 数据入口。
          </li>
          <li>
            <InlineCode>34780-34781/udp</InlineCode>：独立 RFC 5780 STUN 的 P1/P2；主、备服务器分别提供 A1/A2，四个组合均需可达。
          </li>
          <li>
            <InlineCode>49152-65535/udp</InlineCode>：TURN relay 默认分配范围，可用服务端 relay min/max 配置收窄。
          </li>
        </ul>
        <CodeCard language="bash" title="防火墙" code={`# specus-server
sudo firewall-cmd --add-port=3478/udp --permanent
sudo firewall-cmd --add-port=49152-65535/udp --permanent

# stun1 / stun2 两台独立 STUN 主机
sudo firewall-cmd --add-port=34780-34781/udp --permanent
sudo firewall-cmd --reload`} />
      </DocSection>

      <DocSection title="检测链路" description="原生客户端复用 peer mesh 业务 UDP socket 执行 RFC 5780，避免独立探测 socket 得到与真实数据面不一致的映射。">
        <ol className="ms-steps ms-steps--compact">
          {[
            ["1", "发现拓扑", "向 A1:P1 Binding，从 RESPONSE-ORIGIN 与 OTHER-ADDRESS 获取 RFC 5780 四端点。"],
            ["2", "过滤测试", "依次请求变更 IP+端口、仅变更端口，分类 EIF、ADF 或 APDF。"],
            ["3", "映射测试", "向 A2:P1、A2:P2 普通 Binding，比较映射并分类 EIM、ADM 或 APDM。"],
            ["4", "上报与选路", "分别上报 mapping/filtering/discovery；ICE 实测直连失败后使用认证 TURN。"],
          ].map(([index, title, text]) => (
            <DocStep key={index} index={Number(index)} title={title}>
              <p>{text}</p>
            </DocStep>
          ))}
        </ol>
      </DocSection>

      <DocSection id={HELP_NAT_TYPES_ANCHOR} title="NAT 行为速查" description="RFC 5780 将 NAT 分成映射与过滤两个独立轴；控制台优先展示双轴结果，再给出路径建议。">
        <div className="ms-axis-grid ms-block">
          {NAT_BEHAVIOR_AXES.map((axis) => (
            <Card key={axis.key} className="ms-axis">
              <div className="ms-axis-head">
                <h3 className="bd-card-title">{axis.title}</h3>
                <p className="app-card-desc">{axis.subtitle}</p>
              </div>
              <ul className="ms-axis-list">
                {axis.items.map((item) => (
                  <li key={item.code}>
                    <span className="ms-axis-code">{item.code}</span>
                    <span className="min-w-0">
                      <span className="ms-strong">{item.label}</span>
                      <span className="ms-axis-detail">{item.detail}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
        <TableWrap className="ms-block">
          <table className="bd-table jd-stack ms-table" aria-label="NAT 组合与路径建议">
            <thead>
              <tr>
                <th scope="col">组合</th>
                <th scope="col">路径</th>
                <th scope="col">说明</th>
              </tr>
            </thead>
            <tbody>
              {NAT_PATH_GUIDANCE.map((item) => (
                <tr key={item.label}>
                  <td><span className="ms-mono ms-strong">{item.label}</span></td>
                  <td><ModelTag color={item.tone}>{item.path}</ModelTag></td>
                  <td className="ms-wrap ms-doc-cell">{item.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
        <p className="ms-doc-note">
          <InlineCode>natType</InlineCode> 仅保留给旧客户端和旧界面兼容；路径策略以 mapping/filtering 字段及实际 ICE 连通性为准。
        </p>
      </DocSection>

      <DocSection
        title="NAT 穿透说明"
        description="根据 Tailscale NAT traversal 文章做中文改写。"
        actions={(
          <Button
            as="a"
            href={NAT_TRAVERSAL_REFERENCE.url}
            rel="noreferrer"
            target="_blank"
            size="sm"
            variant="flat"
            endContent={<Icon name="external" size={14} />}
          >
            阅读原文
          </Button>
        )}
      >
        <div className="ms-note-grid">
          {NAT_TRAVERSAL_REFERENCE.notes.map((note) => (
            <Card key={note.title} className="ms-note-card">
              <h3 className="ms-note-title">{note.title}</h3>
              <p>{note.text}</p>
            </Card>
          ))}
        </div>
      </DocSection>

      <DocSection title="虚拟网卡要求">
        <ul className="ms-doc-list">
          <li>Linux：需要 root 或 <InlineCode>CAP_NET_ADMIN</InlineCode>，系统需要 <InlineCode>/dev/net/tun</InlineCode>。</li>
          <li>Windows：需要管理员权限。客户端已内置 Wintun DLL，会优先从程序资源释放到本地后加载。</li>
          <li>失败时客户端会回退 <InlineCode>noop</InlineCode> 并把虚拟网卡状态上报到「私有组网」页面。</li>
        </ul>
      </DocSection>
    </>
  );
}

function ProtocolSection() {
  return (
    <>
      <DocSection title="端口规划">
        <TableWrap>
          <table className="bd-table jd-stack ms-table" aria-label="端口规划">
            <thead>
              <tr>
                <th scope="col">端口</th>
                <th scope="col">用途</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><InlineCode>7010</InlineCode></td>
                <td className="ms-wrap ms-doc-cell">控制连接端口，客户端连接此端口完成登录、心跳、隧道管理。通过环境变量 <InlineCode>SPECUS_NETTY_PORT</InlineCode> 覆盖。</td>
              </tr>
              <tr>
                <td><InlineCode>8088</InlineCode></td>
                <td className="ms-wrap ms-doc-cell">管理后台 + HTTP 直转入口。<InlineCode>/http/&#123;client&#125;/&#123;route&#125;/...</InlineCode> 为公开流量入口。</td>
              </tr>
              <tr>
                <td><span className="jd-muted">自定义</span></td>
                <td className="ms-wrap ms-doc-cell">各「端口映射」自定义的公网监听端口（如 9000）。</td>
              </tr>
              <tr>
                <td><InlineCode>3478/udp</InlineCode></td>
                <td className="ms-wrap ms-doc-cell">specus-server 的认证 TURN 控制端口。通过环境变量 <InlineCode>SPECUS_PEER_MESH_STUN_TURN_PORT</InlineCode> 覆盖。</td>
              </tr>
              <tr>
                <td><InlineCode>34780-34781/udp</InlineCode></td>
                <td className="ms-wrap ms-doc-cell">独立 RFC 5780 STUN 的 P1/P2，需在 A1/A2 两个公网地址同时开放。</td>
              </tr>
              <tr>
                <td><InlineCode>49152-65535/udp</InlineCode></td>
                <td className="ms-wrap ms-doc-cell">TURN relay 默认分配范围。</td>
              </tr>
            </tbody>
          </table>
        </TableWrap>
      </DocSection>

      <DocSection title="协议">
        <p>
          控制连接走自定义二进制协议，默认 11 字节头（magic / version / serializer / command / length），
          消息体采用紧凑二进制序列化，必要时启用 deflate 压缩。客户端实现之间字节级兼容。
          Peer mesh 信令复用控制连接的 <InlineCode>PEER_CONTROL</InlineCode>，数据面优先 UDP 直连，失败后走内置标准 TURN 子集 relay。
        </p>
      </DocSection>

      <DocSection title="控制连接 TLS" description="通过 SPECUS_TLS_MODE 环境变量切换。">
        <ul className="ms-doc-list">
          <li>
            <InlineCode>disabled</InlineCode>（默认）—— 明文 TCP，与旧部署兼容
          </li>
          <li>
            <InlineCode>file</InlineCode> —— 从磁盘加载 keystore（生产用）
          </li>
          <li>
            <InlineCode>self-signed</InlineCode> —— 启动时生成一次性自签名证书（开发/测试用）
          </li>
        </ul>
      </DocSection>
    </>
  );
}

function FaqSection() {
  return (
    <DocSection title="常见问题" description="展开一条看原因和处理办法。">
      <div className="ms-folds">
        <Fold title="客户端显示「客户端不在线」" icon="circle-alert">
          <ul className="ms-doc-list">
            <li>检查 <InlineCode>serverBaseUrl</InlineCode> 是否能访问服务端管理 HTTP 地址</li>
            <li>检查服务端登录响应里的控制连接地址和端口是否可达，默认控制端口为 7010</li>
            <li>检查防火墙是否放行 7010</li>
            <li>检查客户端日志：登录失败一般是 API Key / Secret 不对，或 Secret 包含尾随空白字符</li>
            <li>服务端 TLS 启用后，客户端必须同步启用 TLS 才能握手</li>
          </ul>
        </Fold>

        <Fold title="HTTP 直转访问内网应用路径丢失" icon="circle-alert">
          <p>
            内网应用返回的 HTML/CSS 中包含绝对路径（如 <InlineCode>/assets/x.js</InlineCode>），公网访问时会指向根路径而非隧道前缀。
            解决方案：进入「HTTP 路由」编辑目标路由，开启「路径改写」开关。
            服务端会自动改写 HTML/CSS，并向 HTML 注入运行时 polyfill 拦截 fetch / XHR / setAttribute 等 API，
            让 SPA 动态拼接的 URL 也走隧道。
          </p>
        </Fold>

        <Fold title="内网 HTTPS 自签证书报错" icon="circle-alert">
          <p>
            客户端在 HTTP 直转通道访问内网 <InlineCode>https://</InlineCode> 服务时，默认信任所有证书并跳过 hostname 校验。
            仅作为隧道客户端，不会影响管理后台与公网 TLS 的安全性。
          </p>
        </Fold>

        <Fold title="登录管理后台后频繁掉线" icon="circle-alert">
          <p>
            管理后台 JWT 默认 8 小时有效。通过环境变量 <InlineCode>SPECUS_AUTH_TOKEN_TTL_SECONDS</InlineCode>
            调整本地密码登录的令牌时长。
          </p>
        </Fold>

        <Fold title="一台机器多个客户端实例" icon="circle-alert">
          <p>
            服务端会按用户和机器限制同一台机器上的实例数量，默认同一用户最多 2 个在线实例。
            同一机器重复启动时，服务端会拒绝超过限制的连接；停止旧实例后可重新登录。
          </p>
        </Fold>

        <Fold title="私有组网一直显示 NAT 未知" icon="circle-alert">
          <ul className="ms-doc-list">
            <li>确认服务端已启用 <InlineCode>SPECUS_PEER_MESH_ENABLED=true</InlineCode>，并且客户端在「私有组网」页面已启用。</li>
            <li>确认 <InlineCode>A1:P1</InlineCode>、<InlineCode>A1:P2</InlineCode>、<InlineCode>A2:P1</InlineCode>、<InlineCode>A2:P2</InlineCode> 四个独立 STUN 端点都可达。</li>
            <li>确认 A1:P1 的 Binding Success 同时返回 <InlineCode>RESPONSE-ORIGIN</InlineCode> 与 <InlineCode>OTHER-ADDRESS</InlineCode>。</li>
            <li>确认 specus-server 已配置独立 STUN 主、备地址和端口，并在客户端登录响应中下发。</li>
            <li>客户端需支持并上报 <InlineCode>natBehaviorDiscovery=RFC5780</InlineCode>；只有基础结果时会显示兼容标签。</li>
          </ul>
        </Fold>
      </div>
      <Alert tone="info" title="这里没有你的问题" className="ms-doc-after">
        查看客户端日志里的出错原因；涉及私有组网的，先到「私有组网 → NAT 诊断」看各设备的检测结果。
      </Alert>
    </DocSection>
  );
}

// ---- 通用 UI 部件 ----

function DocSection({ title, description, actions, id, children }: {
  title: ReactNode; description?: ReactNode; actions?: ReactNode; id?: string; children: ReactNode;
}) {
  return (
    <Section id={id} title={title} description={description} actions={actions} className="ms-doc-section">
      <div className="ms-doc-body">{children}</div>
    </Section>
  );
}

function DocStep({ index, title, children }: { index: number; title: string; children: ReactNode }) {
  return (
    <li className="ms-step">
      <span className="ms-step-num bd-num" aria-hidden="true">{index}</span>
      <div className="ms-step-body">
        <h3 className="ms-step-title">{title}</h3>
        {children}
      </div>
    </li>
  );
}

function DocLabel({ children }: { children: ReactNode }) {
  return <p className="ms-doc-label">{children}</p>;
}

// 共享配置示例（与 README.md "client.jsonc" 样例保持一致）
const SAMPLE_CONFIG = `{
  "$schema": "https://specus.devshuai.com/schemas/client-startup-config.schema.json",
  // 服务端管理 HTTP 地址
  "serverBaseUrl": "https://specus.example.com",
  "apiKey": "your-api-key",
  "secret": "paste-the-one-time-secret-here",
}`;

const PEER_MESH_CONFIG = `{
  "$schema": "https://specus.devshuai.com/schemas/client-startup-config.schema.json",
  // 服务端管理 HTTP 地址
  "serverBaseUrl": "https://specus.example.com",
  "apiKey": "your-api-key",
  "secret": "paste-the-one-time-secret-here",
  "peerMeshDevice": "auto",
  "peerMeshTunName": "specus0",
  "peerMeshMtu": 1280,
}`;
