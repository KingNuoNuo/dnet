/* ==========================================================================
   页面级 tab —— 配合 common.css 的 .dnet-tabs / .dnet-panel
   --------------------------------------------------------------------------
   用法（写在页面里）：

     <div class="layui-container" data-tabs>
         <div class="dnet-tabs">
             <button type="button" data-tab="basic">基础设置</button>
             <button type="button" data-tab="vendor">服务商</button>
         </div>
         <form class="layui-form">
             <div class="layui-card dnet-panel on" data-panel="basic">…</div>
             <div class="layui-card dnet-panel"    data-panel="vendor">…</div>
         </form>
     </div>

   【为什么初始化要卡在 layui 之后】
   layui 把 <select> 渲染成 .layui-form-select，宽度按容器实测算。
   若面板在它渲染前就已经 display:none，量到的宽度是 0，
   切回来就是一个塌掉的下拉框。所以 CSS 里「收起非激活面板」的规则挂在
   html.dnet-tabs-ready 上 —— 本脚本在 layui 渲染完成后再加这个类，
   在那之前所有面板都是可见的。

   【为什么是 layui.use 而不是 DOMContentLoaded】
   layui 的回调队列按注册先后执行。本文件排在页面自身的 <script> 之后加载，
   因此回调必然晚于页面的初始化，此时下拉/开关都已渲染完毕。
   ========================================================================== */
(function () {
    'use strict';

    function attr(el, name) {
        return el.getAttribute(name) || '';
    }

    function initTabs(root) {
        var tabs = Array.prototype.slice.call(root.querySelectorAll('.dnet-tabs button'));
        var panels = Array.prototype.slice.call(root.querySelectorAll('.dnet-panel'));

        if (!tabs.length || !panels.length) {
            return;
        }

        function select(key, focus) {
            var found = false;

            tabs.forEach(function (btn) {
                var on = attr(btn, 'data-tab') === key;
                btn.classList.toggle('on', on);
                btn.setAttribute('aria-selected', on ? 'true' : 'false');
                btn.setAttribute('tabindex', on ? '0' : '-1');
                if (on) {
                    found = true;
                }
            });

            if (!found) {
                return;
            }

            panels.forEach(function (panel) {
                panel.classList.toggle('on', attr(panel, 'data-panel') === key);
            });

            // 记住当前位置：刷新、切回模块时不会跳回第一格
            try {
                history.replaceState(null, '', '#' + key);
            } catch (e) {
                /* file:// 等场景下 replaceState 不可用，忽略 */
            }
        }

        tabs.forEach(function (btn, i) {
            btn.setAttribute('role', 'tab');
            btn.setAttribute('type', 'button');

            btn.addEventListener('click', function () {
                select(attr(btn, 'data-tab'));
            });

            // 左右方向键切换，符合 tablist 的无障碍预期
            btn.addEventListener('keydown', function (e) {
                var next = null;
                if (e.key === 'ArrowRight') {
                    next = tabs[(i + 1) % tabs.length];
                } else if (e.key === 'ArrowLeft') {
                    next = tabs[(i - 1 + tabs.length) % tabs.length];
                }
                if (next) {
                    e.preventDefault();
                    next.focus();
                    select(attr(next, 'data-tab'));
                }
            });
        });

        var hash = decodeURIComponent((location.hash || '').replace(/^#/, ''));
        var known = tabs.some(function (btn) {
            return attr(btn, 'data-tab') === hash;
        });

        select(known ? hash : attr(tabs[0], 'data-tab'));

        // 面板内的锚点跳转（如校验失败 focus）需要先让对应面板可见，
        // 这里对外暴露一个按元素反查并激活的方法。
        root.dnetShowTabOf = function (el) {
            var panel = el && el.closest ? el.closest('.dnet-panel') : null;
            if (panel) {
                select(attr(panel, 'data-panel'));
            }
        };
    }

    function boot() {
        Array.prototype.forEach.call(
            document.querySelectorAll('[data-tabs]'),
            initTabs
        );
        // 初始化完成，此后才允许 CSS 收起非激活面板
        document.documentElement.classList.add('dnet-tabs-ready');
    }

    if (window.layui && layui.use) {
        layui.use(['form'], boot);
    } else if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
}());
