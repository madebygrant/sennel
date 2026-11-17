import { mount } from "svelte";
import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/chakra-petch/latin-600.css";
import Popup from "./Popup.svelte";
import "./popup.css";

mount(Popup, { target: document.getElementById("app") });
