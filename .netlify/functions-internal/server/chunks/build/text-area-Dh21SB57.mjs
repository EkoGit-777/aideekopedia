import { defineComponent, mergeModels, useModel, mergeProps, useSSRContext } from 'vue';
import { ssrRenderAttrs, ssrInterpolate, ssrRenderAttr } from 'vue/server-renderer';

const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "text-area",
  __ssrInlineRender: true,
  props: /* @__PURE__ */ mergeModels({
    placeholder: {}
  }, {
    "modelValue": { default: null },
    "modelModifiers": {}
  }),
  emits: /* @__PURE__ */ mergeModels(["enter"], ["update:modelValue"]),
  setup(__props, { emit: __emit }) {
    const textArea = useModel(__props, "modelValue");
    return (_ctx, _push, _parent, _attrs) => {
      _push(`<div${ssrRenderAttrs(mergeProps({ class: "relative box-border max-h-256 min-h-36 w-full flex overflow-hidden" }, _attrs))}><div class="w-full whitespace-pre-line break-words text-justify">${ssrInterpolate(textArea.value)}</div><textarea name="inputTextArea" class="absolute box-border bottom-0 top-0 w-full rounded-12 resize-none overflow-y-auto px-8 py-4 focus:outline-none" rows="2"${ssrRenderAttr("placeholder", __props.placeholder)}>${ssrInterpolate(textArea.value)}</textarea></div>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/input/text-area.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};

export { _sfc_main as _ };
//# sourceMappingURL=text-area-Dh21SB57.mjs.map
