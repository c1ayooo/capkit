package icpkit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"strings"
	"testing"

	"github.com/c1ayooo/capkit"
)

// fakeFetcher 按 URL 返回预置响应，模拟 beian 上游。
type fakeFetcher struct {
	responses map[string]string
	calls     []capkit.Request
}

func (f *fakeFetcher) Fetch(_ context.Context, req capkit.Request) (*capkit.Response, error) {
	f.calls = append(f.calls, req)
	body, ok := f.responses[req.URL]
	if !ok {
		body = `{}`
	}
	return &capkit.Response{Status: 200, Body: []byte(body)}, nil
}

func (f *fakeFetcher) urls() []string {
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.URL)
	}
	return out
}

// 默认响应：auth 发 token；验证码图片故意不可解，使客户端退化到兜底 sign；
// queryByCondition 返回一条百度备案记录。
func defaultFetcher() *fakeFetcher {
	return &fakeFetcher{responses: map[string]string{
		authEndpoint:     `{"success":true,"params":{"bussiness":"TOKEN-XYZ","expire":3600000}}`,
		checkImagePoint:  `{"success":true,"params":{"uuid":"u-1","bigImage":"!!!!","smallImage":"!!!!"}}`,
		queryByCondition: `{"success":true,"code":200,"params":{"total":1,"list":[{"unitName":"北京百度网讯科技有限公司","domain":"baidu.com","serviceType":1}]}}`,
	}}
}

func TestManifestValidates(t *testing.T) {
	kit := New(capkit.Deps{Fetcher: defaultFetcher()})
	reg := capkit.NewRegistry()
	if err := reg.Add(capkit.Spec{Manifest: kit.Manifest(), New: NewCapability}); err != nil {
		t.Fatalf("registry.Add: %v", err)
	}
	if err := reg.Validate(capkit.Deps{Fetcher: defaultFetcher()}); err != nil {
		t.Fatalf("registry.Validate: %v", err)
	}
	tools := kit.Manifest().Tools
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(tools))
	}
	for _, tool := range tools {
		if tool.ExtractTargets == nil {
			t.Errorf("tool %s: ExtractTargets 必须显式声明为非 nil（返回空）", tool.Name)
		}
		if tg, err := tool.ExtractTargets(nil); err != nil || tg != nil {
			t.Errorf("tool %s: 非目标工具应返回 (nil,nil)，得到 (%v,%v)", tool.Name, tg, err)
		}
	}
}

func TestNewCapabilityRequiresFetcher(t *testing.T) {
	if _, err := NewCapability(capkit.Deps{}); err == nil {
		t.Fatal("缺少 fetcher 时 NewCapability 应报错")
	}
}

func TestQueryWeb(t *testing.T) {
	ff := defaultFetcher()
	kit := New(capkit.Deps{Fetcher: ff})
	res, err := kit.Call(context.Background(), capkit.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"baidu.com","type":"web"}`),
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !res.OK {
		t.Fatalf("查询失败: %+v", res.Error)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("解析结果: %v", err)
	}
	if out["type"] != "web" || out["count"] != float64(1) {
		t.Fatalf("非预期结果: %s", res.Data)
	}
	// 必须经过 auth -> (验证码失败) -> 兜底 sign -> queryByCondition。
	urls := strings.Join(ff.urls(), "\n")
	for _, want := range []string{authEndpoint, checkImagePoint, queryByCondition} {
		if !strings.Contains(urls, want) {
			t.Errorf("未调用 %s，实际: %v", want, ff.urls())
		}
	}
}

func TestQueryBlacklistDomain(t *testing.T) {
	ff := defaultFetcher()
	ff.responses[blackByCondition] = `{"success":true,"code":200,"params":{"list":[{"domain":"evil.com"}]}}`
	kit := New(capkit.Deps{Fetcher: ff})
	res, err := kit.Call(context.Background(), capkit.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"evil.com","type":"bweb"}`),
	})
	if err != nil || !res.OK {
		t.Fatalf("黑名单查询失败: err=%v res=%+v", err, res)
	}
	if !strings.Contains(strings.Join(ff.urls(), "\n"), blackByCondition) {
		t.Fatalf("未命中黑名单端点: %v", ff.urls())
	}
}

func TestAppDetailFanout(t *testing.T) {
	ff := defaultFetcher()
	ff.responses[queryByCondition] = `{"success":true,"code":200,"params":{"list":[
		{"dataId":1001,"serviceType":6},
		{"dataId":1002,"serviceType":6}
	]}}`
	ff.responses[appDetailEndpoint] = `{"success":true,"params":{"dataId":1001,"domain":"detail.example","appName":"X"}}`
	kit := New(capkit.Deps{Fetcher: ff})
	res, err := kit.Call(context.Background(), capkit.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"某App","type":"app"}`),
	})
	if err != nil || !res.OK {
		t.Fatalf("App 查询失败: err=%v res=%+v", err, res)
	}
	var out struct {
		Result struct {
			Params struct {
				List []map[string]any `json:"list"`
			} `json:"params"`
		} `json:"result"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("解析: %v", err)
	}
	if len(out.Result.Params.List) != 2 {
		t.Fatalf("期望 2 条，得到 %d", len(out.Result.Params.List))
	}
	if out.Result.Params.List[0]["domain"] != "detail.example" {
		t.Errorf("首条未替换为详情: %v", out.Result.Params.List[0])
	}
}

func TestRejectsUnsupportedType(t *testing.T) {
	kit := New(capkit.Deps{Fetcher: defaultFetcher()})
	res, _ := kit.Call(context.Background(), capkit.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"x","type":"nope"}`),
	})
	if res.OK || res.Error == nil || res.Error.Code != capkit.CodeInvalidInput {
		t.Fatalf("非法类型应报 invalid_input: %+v", res)
	}
}

func TestTypesTool(t *testing.T) {
	kit := New(capkit.Deps{Fetcher: defaultFetcher()})
	res, err := kit.Call(context.Background(), capkit.Call{Tool: "icp_types"})
	if err != nil || !res.OK {
		t.Fatalf("icp_types 失败: err=%v res=%+v", err, res)
	}
	if !strings.Contains(string(res.Data), `"bweb"`) {
		t.Fatalf("类型目录缺少 bweb: %s", res.Data)
	}
}

func TestWAFBlockSurfacesError(t *testing.T) {
	ff := defaultFetcher()
	ff.responses[authEndpoint] = `<html>当前访问疑似黑客攻击</html>`
	kit := New(capkit.Deps{Fetcher: ff})
	res, _ := kit.Call(context.Background(), capkit.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"baidu.com"}`),
	})
	if res.OK || res.Error == nil || !strings.Contains(res.Error.Message, "创宇盾") {
		t.Fatalf("应识别创宇盾拦截: %+v", res)
	}
}

// ---- 滑块缺口定位 ----

// makePNG 编码一张 PNG 并返回 base64（与上游验证码字段一致）。
func makePNG(t *testing.T, img image.Image) string {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// TestMatchSliderOffset 构造噪声背景 + 纯色缺口方块，验证定位到原始 x 偏移。
func TestMatchSliderOffset(t *testing.T) {
	const bw, bh = 300, 150
	const gapX0, gapY0, gapSide = 100, 40, 50

	big := image.NewRGBA(image.Rect(0, 0, bw, bh))
	rng := rand.New(rand.NewSource(7))
	for y := 0; y < bh; y++ {
		for x := 0; x < bw; x++ {
			big.Set(x, y, color.RGBA{uint8(rng.Intn(256)), uint8(rng.Intn(256)), uint8(rng.Intn(256)), 255})
		}
	}
	gapColor := color.RGBA{200, 20, 20, 255}
	for y := gapY0; y < gapY0+gapSide; y++ {
		for x := gapX0; x < gapX0+gapSide; x++ {
			big.Set(x, y, gapColor)
		}
	}
	small := image.NewRGBA(image.Rect(0, 0, gapSide, gapSide))

	got, err := matchSliderOffset(makePNG(t, small), makePNG(t, big))
	if err != nil {
		t.Fatalf("matchSliderOffset: %v", err)
	}
	if got != gapX0 {
		t.Fatalf("缺口 x 期望 %d，得到 %d", gapX0, got)
	}
}
