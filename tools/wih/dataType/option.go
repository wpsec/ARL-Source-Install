package dataType

// Option 定义 wih 命令行参数集合。
// 说明：
// - 字段覆盖 ARL 当前调用参数与历史 wih 常用参数。
// - 一部分历史参数仅做兼容透传（不参与核心逻辑）。
type Option struct {
	Target       string // -t, --target：目标 URL 或文件路径
	URL          string // -u, --url：单个 URL（兼容输入）
	FilePath     string // --file-path：文件路径（兼容输入）
	JsonFilePath string // --json-path：JSON 路径（兼容输入）

	RuleConfigPath      string // -r, --rule-config：规则文件路径
	OutputFilePath      string // -o, --output：输出文件路径（- 表示标准输出）
	EndpointOutputPath  string // --endpoint-output：结构化接口输出文件
	ParameterOutputPath string // --parameter-output：结构化参数输出文件
	OutputSize          int    // --size：分页大小（兼容参数）

	Proxy string // -x, --proxy：代理地址

	Concurrency        int  // -c, --concurrency：站点并发
	ConcurrencyPerSite int  // -P, --concurrency-per-site：单站并发
	MaxCollect         int  // -M, --max-collect：每站最多收集条数
	LimitReaderSize    int  // --limit-reader-size：响应体读取上限（字节）
	MaxJSFiles         int  // 内部参数：每站最多抓取 JS 文件数量
	RuntimeEnable      bool // --runtime-enable：启用运行时参数采集骨架
	RuntimeMaxPages    int  // --runtime-max-pages：运行时最大页面数
	RuntimeMaxActions  int  // --runtime-max-actions：运行时最大交互动作数
	RuntimeMaxRequests int  // --runtime-max-requests：运行时最大采集请求数

	TimeOutSec     float64 // --timeout：请求超时（秒）
	DialTimeOutSec float64 // --dial-timeout：连接超时（秒）

	LogLevel string // -v, --log-level：日志等级
	LogFile  string // --log-file：日志输出路径（- 表示不落盘）

	HeaderRaw []string // -H, --header：自定义请求头（可重复）

	OutputJSON              bool // -J, --output-json：JSON 行输出
	OutputCSV               bool // --csv：CSV 输出
	OutputHTML              bool // --html：HTML 输出
	OutputMD                bool // --md：Markdown 输出
	OutputText              bool // -T, --text：文本输出
	DisableStructuredOutput bool // --disable-structured-output：禁用 endpoint/parameter 独立输出

	DisableColor bool // --disable-color：禁用彩色输出
	Debug        bool // --debug：调试日志开关

	FollowRedirect bool // -f, --follow-redirect：跟随重定向
	GenerateRule   bool // -G, --generate-rule：输出规则模板
	ShowVersion    bool // --version：显示版本并退出

	AKSKOutputPath      string // --ak-sk-output：AK/SK 输出文件（兼容参数）
	AutoSaveName        bool   // -a, --auto-save-name：按站点自动命名（兼容参数）
	DisableAKSKOutput   bool   // --disable-ak-sk-output：禁用 AK/SK 单独保存（兼容参数）
	DisableCheckAKSK    bool   // --disable-check-ak-sk：禁用 AK/SK 有效性校验（兼容参数）
	DisableCheckAKSKAlt bool   // --dc：禁用 AK/SK 有效性校验（兼容短参数）
}
