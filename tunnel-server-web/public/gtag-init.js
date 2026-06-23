// Google Analytics gtag.js 初始化。
// 抽到独立同源文件而不是内联到 index.html，避免与 CSP 的 script-src 'self' 冲突，
// 也避免在压缩/格式化后 sha256 hash 失效。
// 主 loader（googletagmanager.com/gtag/js）通过 CSP 单独放行域名加载。
window.dataLayer = window.dataLayer || [];
function gtag() {
  window.dataLayer.push(arguments);
}
window.gtag = gtag;
gtag('js', new Date());
gtag('config', 'G-TNJRNXHJ40');
