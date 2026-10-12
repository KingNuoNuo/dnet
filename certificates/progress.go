package certificates

import "context"

// 申请进度上报：issue() 在各阶段调用 report()，Web 层通过 WithProgress
// 注入回调把当前步骤记到内存里，供证书列表接口悬浮展示。
// 纯库场景（无回调）零开销，进度上报是可选能力。

type progressKey struct{}

// ProgressFunc 接收当前步骤描述（中文短句）。
type ProgressFunc func(step string)

func WithProgress(ctx context.Context, fn ProgressFunc) context.Context {
	return context.WithValue(ctx, progressKey{}, fn)
}

func reportProgress(ctx context.Context, step string) {
	if fn, ok := ctx.Value(progressKey{}).(ProgressFunc); ok && fn != nil {
		fn(step)
	}
}
