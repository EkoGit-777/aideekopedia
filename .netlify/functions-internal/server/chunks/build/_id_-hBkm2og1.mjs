import { _ as _sfc_main$1 } from './text-area-Dh21SB57.mjs';
import { defineComponent, ref, mergeProps, unref, useSSRContext } from 'vue';
import { ssrRenderAttrs, ssrRenderList, ssrRenderClass, ssrInterpolate, ssrRenderComponent } from 'vue/server-renderer';
import { Chat } from '@ai-sdk/vue';
import { u as useRoute, a as useRouter } from './server.mjs';
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

const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "[id]",
  __ssrInlineRender: true,
  setup(__props) {
    const query = ref("");
    const chat = new Chat({});
    useRoute();
    useRouter();
    const handleSubmit = () => {
      chat.sendMessage({ text: query.value });
      query.value = "";
    };
    return (_ctx, _push, _parent, _attrs) => {
      const _component_input_text_area = _sfc_main$1;
      _push(`<div${ssrRenderAttrs(mergeProps({ class: "relative box-border flex-col flex w-full justify-center px-24 md:px-128 h-full space-y-12 items-center" }, _attrs))}><div class="space-y-8 flex-1 flex-col w-full py-24 overflow-y-auto"><!--[-->`);
      ssrRenderList(unref(chat).messages, (m, index) => {
        _push(`<div class="${ssrRenderClass([{ "justify-end": m.role === "user" }, "w-full text-white flex"])}"><!--[-->`);
        ssrRenderList(m.parts, (part, index2) => {
          _push(`<div class="${ssrRenderClass({ "bg-yellow text-black rounded-8 p-8": m.role === "user" })}">`);
          if (part.type === "text") {
            _push(`<div>${ssrInterpolate(part.text)}</div>`);
          } else {
            _push(`<!---->`);
          }
          _push(`</div>`);
        });
        _push(`<!--]--></div>`);
      });
      _push(`<!--]--></div><div class="py-24 w-full">`);
      _push(ssrRenderComponent(_component_input_text_area, {
        class: "w-full bottom-24 px-8 py-4 text12 rounded-12",
        placeholder: "Ask me anything",
        modelValue: query.value,
        "onUpdate:modelValue": ($event) => query.value = $event,
        onEnter: handleSubmit
      }, null, _parent));
      _push(`</div></div>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/[id].vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};

export { _sfc_main as default };
//# sourceMappingURL=_id_-hBkm2og1.mjs.map
