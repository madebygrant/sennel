<script>
  import { onMount } from "svelte";

  // A native modal dialog: the page behind goes inert, Tab stays inside, and Esc asks `onclose`.
  let { label, onclose, children } = $props();
  let dialog;

  onMount(() => {
    const opener = document.activeElement;
    dialog.showModal();
    return () => opener?.focus?.();
  });

  function cancel(event) {
    event.preventDefault();
    onclose();
  }

  // A repeated Esc may close the dialog anyway; reopen it so it stays in step with the component.
  function closed() {
    if (!dialog.isConnected) return;
    dialog.showModal();
    onclose();
  }
</script>

<dialog bind:this={dialog} aria-label={label} oncancel={cancel} onclose={closed}>
  {@render children()}
</dialog>

<style>
  dialog {
    padding: 0;
    border: 0;
    background: none;
    color: inherit;
    max-width: calc(100vw - 40px);
    max-height: calc(100vh - 40px);
    overflow: visible;
  }

  dialog::backdrop {
    background: rgb(0 0 0 / 0.5);
  }
</style>
