<script setup lang="ts">
import { useVModel } from "@vueuse/core";
import { ChevronDown } from "lucide-vue-next";
import { computed, type HTMLAttributes } from "vue";

import { cn } from "../../../lib/cn";

/**
 * A styled native select. Native keeps the OS picker, type-ahead and mobile behaviour for free,
 * which is the right trade for short closed lists inside forms.
 */
const props = withDefaults(
  defineProps<{
    modelValue?: string;
    disabled?: boolean;
    invalid?: boolean;
    class?: HTMLAttributes["class"];
  }>(),
  { disabled: false, invalid: false },
);

const emits = defineEmits<{ "update:modelValue": [value: string] }>();
const model = useVModel(props, "modelValue", emits, { passive: true });

const classes = computed(() =>
  cn(
    "h-8 w-full appearance-none rounded-md border border-rule bg-surface pl-2.5 pr-8 text-[13px] text-ink",
    "transition-[border-color,box-shadow] duration-100 hover:border-rule-strong",
    "focus-visible:border-brand focus-visible:ring-[3px] focus-visible:ring-brand/15",
    "disabled:cursor-not-allowed disabled:opacity-50",
    props.invalid && "border-deny",
    props.class,
  ),
);
</script>

<template>
  <div class="relative">
    <select v-model="model" :class="classes" :disabled="disabled" :aria-invalid="invalid || undefined">
      <slot />
    </select>
    <ChevronDown
      class="pointer-events-none absolute right-2.5 top-1/2 size-3.5 -translate-y-1/2 text-ink-faint"
      aria-hidden="true"
    />
  </div>
</template>
