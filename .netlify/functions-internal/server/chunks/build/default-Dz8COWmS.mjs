import { _ as __nuxt_component_0 } from './nuxt-link-DAtzttks.mjs';
import { defineComponent, ref, watch, mergeProps, withCtx, createTextVNode, unref, toDisplayString, useSSRContext } from 'vue';
import { ssrRenderAttrs, ssrRenderComponent, ssrRenderList, ssrInterpolate } from 'vue/server-renderer';
import { u as useSessionStore } from './sessions-Ch2qXTsx.mjs';
import { u as useRoute, b as __nuxt_component_1$1, c as __nuxt_component_2 } from './server.mjs';
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

const _sfc_main$1 = /* @__PURE__ */ defineComponent({
  __name: "sidemenu",
  __ssrInlineRender: true,
  setup(__props) {
    const sessionStore = useSessionStore();
    return (_ctx, _push, _parent, _attrs) => {
      const _component_NuxtLink = __nuxt_component_0;
      _push(`<div${ssrRenderAttrs(mergeProps({ class: "flex flex-col h-full" }, _attrs))}><div class="p-4 border-b"><h2 class="text20 font-bold text-yellow">AideEkopedia</h2></div><nav class="flex-1 overflow-y-auto p-2 space-y-4">`);
      _push(ssrRenderComponent(_component_NuxtLink, {
        to: "/",
        class: "block p-2 text-yellow hover:bg-primary-400 rounded-lg"
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(` New Chat `);
          } else {
            return [
              createTextVNode(" New Chat ")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`<!--[-->`);
      ssrRenderList(unref(sessionStore).sessions, (session) => {
        _push(ssrRenderComponent(_component_NuxtLink, {
          key: session.id,
          to: `/chat/${session.id}`,
          class: "block p-3 rounded-lg text-yellow hover:bg-primary-400 border"
        }, {
          default: withCtx((_, _push2, _parent2, _scopeId) => {
            if (_push2) {
              _push2(` Chat ${ssrInterpolate(session.title)}`);
            } else {
              return [
                createTextVNode(" Chat " + toDisplayString(session.title), 1)
              ];
            }
          }),
          _: 2
        }, _parent));
      });
      _push(`<!--]--></nav><div class="p-4 border-t">`);
      _push(ssrRenderComponent(_component_NuxtLink, {
        to: "/sign-out",
        class: "block p-2 text-yellow hover:bg-primary-400 rounded-lg"
      }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(` Logout `);
          } else {
            return [
              createTextVNode(" Logout ")
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</div></div>`);
    };
  }
});
const _sfc_setup$1 = _sfc_main$1.setup;
_sfc_main$1.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/control/sidemenu.vue");
  return _sfc_setup$1 ? _sfc_setup$1(props, ctx) : void 0;
};
const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "default",
  __ssrInlineRender: true,
  setup(__props) {
    ref([]);
    const route = useRoute();
    const isOpen = ref(false);
    watch(route, () => {
      isOpen.value = false;
    });
    return (_ctx, _push, _parent, _attrs) => {
      const _component_ControlSidemenu = _sfc_main$1;
      const _component_NuxtLoadingIndicator = __nuxt_component_1$1;
      const _component_NuxtPage = __nuxt_component_2;
      _push(`<div${ssrRenderAttrs(mergeProps({ class: "flex h-screen divide-x divide-yellow" }, _attrs))}><aside class="hidden md:block w-180 bg-primary">`);
      _push(ssrRenderComponent(_component_ControlSidemenu, null, null, _parent));
      _push(`</aside><div class="md:hidden absolute top-4 left-4 z-50"><button class="p-2 bg-blue-600 text-white rounded-lg"> \u2630 </button></div>`);
      if (isOpen.value) {
        _push(`<aside class="fixed inset-y-0 left-0 w-full bg-primary z-40"><div class="py-6 pr-4 pl-32 border-b flex justify-between items-center"><div class="text20 text-yellow font-bold">Chats</div><button class="text-yellow bg-transparent">\u2715</button></div>`);
        _push(ssrRenderComponent(_component_ControlSidemenu, null, null, _parent));
        _push(`</aside>`);
      } else {
        _push(`<!---->`);
      }
      _push(`<main class="flex-1 flex flex-col bg-primary">`);
      _push(ssrRenderComponent(_component_NuxtLoadingIndicator, null, null, _parent));
      _push(ssrRenderComponent(_component_NuxtPage, null, null, _parent));
      _push(`</main></div>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("layouts/default.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};

export { _sfc_main as default };
//# sourceMappingURL=default-Dz8COWmS.mjs.map
