package riskclient

import (
	"net/http"

	"github.com/decodeex/risk-client-go/sdklog"
)

// Option 定制 Client 装配行为,均可在 New(Config, opts...) 变参尾部追加。
// Option 彼此独立、可组合,同一选项重复出现时后者生效。

type option func(*clientSettings)

type clientSettings struct {
	httpClient *http.Client           // WithHTTPClient
	logger     sdklog.Logger          // WithLogger
	requestIP  string                 // WithRequestIP(容器环境必用)
	haveIP     bool                   // 区分「显式置空串」与「未设置」
	traceFn    func() (string, error) // WithTraceIDFunc(测试确定性)
	useTraceFn bool
}

// WithHTTPClient 注入自建的 *http.Client(连接池/代理/自定义 Transport 由宿主编排)。
// 注入后 Config.HTTP 的池参数不再生效——归属一次性转移给调用方。
func WithHTTPClient(hc *http.Client) Option {
	return func(s *clientSettings) { s.httpClient = hc }
}

// WithLogger 注入 SDK 内最小 Logger 接口实现;缺省用 sdklog 默认标准库输出。
// 宿主一行适配桥回自己的 log 包(如 kratos log.Logger → 四个 printf 方法)。
func WithLogger(l sdklog.Logger) Option {
	return func(s *clientSettings) { s.logger = l }
}

// WithRequestIP 显式指定 requestIp 注入值(K8s 多网卡环境强烈建议——自动探测
// 可能取错网卡)。传空串表示刻意发送空值;未调用本选项才走探测兜底。
func WithRequestIP(ip string) Option {
	return func(s *clientSettings) { s.requestIP = ip; s.haveIP = true }
}

// WithTraceIDFunc 注入 traceId 生成函数(测试确定性 / 宿主链路追踪复用)。
// 生产默认 NewUUIDv4()。返回 error 时该次调用以 ErrConfig 语族失败并放弃发网,
// 避免空 traceId 污染签名。
func WithTraceIDFunc(fn func() (string, error)) Option {
	return func(s *clientSettings) { s.traceFn = fn; s.useTraceFn = true }
}

// Option 见各 With* 构造器。
type Option = option
