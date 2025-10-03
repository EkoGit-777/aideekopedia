import { defineComponent, mergeProps, withCtx, createTextVNode, renderSlot, useSSRContext } from 'vue';
import { ssrRenderAttrs, ssrRenderAttr, ssrRenderComponent, ssrRenderSlot } from 'vue/server-renderer';
import { _ as _export_sfc, a as useRouter } from './server.mjs';
import { _ as _imports_0 } from './virtual_public-IWZl7zz2.mjs';
import '../_/nitro.mjs';
import 'node:os';
import 'node:tty';
import 'node:fs';
import 'node:path';
import 'node:crypto';
import 'node:child_process';
import 'node:fs/promises';
import 'node:util';
import 'node:process';
import 'node:async_hooks';
import 'node:events';
import 'path';
import 'fs';
import 'node:http';
import 'node:https';
import 'node:buffer';
import '@logto/node';
import '@silverhand/essentials';
import 'pinia';
import 'vue-router';

const _sfc_main$2 = /* @__PURE__ */ defineComponent({
  __name: "button-index",
  __ssrInlineRender: true,
  props: {
    loading: { type: Boolean, default: false },
    disabled: { type: Boolean, default: false },
    type: { default: "button" }
  },
  setup(__props) {
    return (_ctx, _push, _parent, _attrs) => {
      _push(`<button${ssrRenderAttrs(mergeProps({
        type: __props.type,
        disabled: __props.disabled || __props.loading,
        class: "focus:outline-none"
      }, _attrs))} data-v-f500f1d9>`);
      ssrRenderSlot(_ctx.$slots, "default", {}, null, _push, _parent);
      if (__props.loading) {
        _push(`<span class="dot absolute" data-v-f500f1d9></span>`);
      } else {
        _push(`<!---->`);
      }
      _push(`</button>`);
    };
  }
});
const _sfc_setup$2 = _sfc_main$2.setup;
_sfc_main$2.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/control/button-index.vue");
  return _sfc_setup$2 ? _sfc_setup$2(props, ctx) : void 0;
};
const __nuxt_component_0$1 = /* @__PURE__ */ _export_sfc(_sfc_main$2, [["__scopeId", "data-v-f500f1d9"]]);
const _sfc_main$1 = {};
function _sfc_ssrRender(_ctx, _push, _parent, _attrs) {
  const _component_control_button_index = __nuxt_component_0$1;
  _push(ssrRenderComponent(_component_control_button_index, mergeProps({ class: "bg-gradient-from-blue-700 bg-gradient-to-blue-900 bg-gradient-to-r font-medium text-yellow rounded-8" }, _attrs), {
    default: withCtx((_, _push2, _parent2, _scopeId) => {
      if (_push2) {
        ssrRenderSlot(_ctx.$slots, "default", {}, null, _push2, _parent2, _scopeId);
      } else {
        return [
          renderSlot(_ctx.$slots, "default")
        ];
      }
    }),
    _: 3
  }, _parent));
}
const _sfc_setup$1 = _sfc_main$1.setup;
_sfc_main$1.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/control/button-primary.vue");
  return _sfc_setup$1 ? _sfc_setup$1(props, ctx) : void 0;
};
const __nuxt_component_0 = /* @__PURE__ */ _export_sfc(_sfc_main$1, [["ssrRender", _sfc_ssrRender]]);
const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "login",
  __ssrInlineRender: true,
  setup(__props) {
    const handleLogin = () => {
      const router = useRouter();
      router.push("/sign-in");
    };
    return (_ctx, _push, _parent, _attrs) => {
      const _component_control_button_primary = __nuxt_component_0;
      _push(`<div${ssrRenderAttrs(mergeProps({ class: "h-dvh w-425 flex flex-col justify-center items-center px-64 space-y-16" }, _attrs))}><img${ssrRenderAttr("src", _imports_0)} alt="logo" class="w-96 md:w-108 lg:w-120 xl:w-132"><div class="text20 text-yellow">AideEkopedia</div><form class="w-full space-y-8 bg-white p-16 rounded-8"><div class="text-24 font-bold text-center mb-8">Login</div>`);
      _push(ssrRenderComponent(_component_control_button_primary, {
        class: "w-full p-4",
        onClick: handleLogin
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`Login with Logto`);
          } else {
            return [
              createTextVNode("Login with Logto")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</form></div>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/login.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};

export { _sfc_main as default };
//# sourceMappingURL=login-BoBzO5U-.mjs.map
