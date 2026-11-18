package flow

import (
	"strings"
	"testing"
)

const nestHead = "import { Controller, Get, Post, Query, Body, Redirect, Req } from '@nestjs/common';\nimport dot from 'dot';\n"

// TestJSNestHandlers checks the NestJS rules: a string returned by a
// handler is HTML, @Redirect() returns {url}, a template from the client is
// injection, and a parameter with a decorator that is not a source is not
// tainted.
func TestJSNestHandlers(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"returned string", "class C {\n  @Get('m')\n  m(@Query('name') name: string): string {\n    return `Hello ${name}`;\n  }\n}\n", "taint.js-xss:6"},
		{"returned object", "class C {\n  @Get('m')\n  m(@Query('name') name: string) {\n    return { name };\n  }\n}\n", ""},
		{"escaped string", "class C {\n  @Get('m')\n  m(@Query('name') name: string): string {\n    return `Hello ${encodeURIComponent(name)}`;\n  }\n}\n", ""},
		{"redirect", "class C {\n  @Get('c')\n  @Redirect()\n  c(@Query('next') next?: string) {\n    return { url: next || '/home' };\n  }\n}\n", "taint.js-open-redirect:7"},
		{"redirect fixed", "class C {\n  @Get('c')\n  @Redirect()\n  c(@Query('next') next?: string) {\n    return { url: '/home' };\n  }\n}\n", ""},
		{"template", "class C {\n  @Post('p')\n  p(@Body('template') template: string): string {\n    return dot.template(template)({ a: 1 });\n  }\n}\n", "taint.js-template-injection:6"},
		{"other decorator is not a source", "class C {\n  @Get('m')\n  m(@Req() req: unknown, @CurrentUser() user: string): string {\n    return `Hello ${user}`;\n  }\n}\n", ""},
	} {
		got := strings.Join(jsFlowsIn(t, "c.controller.ts", nestHead+c.body), " ")
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
