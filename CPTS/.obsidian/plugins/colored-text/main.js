/*
THIS IS A GENERATED/BUNDLED FILE BY ESBUILD
if you want to view the source, please visit the github repository of this plugin
*/

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  default: () => ColoredFont
});
module.exports = __toCommonJS(main_exports);
var import_obsidian2 = require("obsidian");

// src/modal.ts
var import_obsidian = require("obsidian");
var ColorModal = class extends import_obsidian.Modal {
  constructor(app, prevColor, onSubmit) {
    super(app);
    this.onSubmit = onSubmit;
    this.prevColor = prevColor;
    this.colorResult = prevColor;
  }
  onOpen() {
    const { contentEl } = this;
    contentEl.createEl("h1", { text: "Color picker" });
    new import_obsidian.Setting(contentEl).setName("Font Color").addColorPicker((color) => color.setValue(this.prevColor).onChange((value) => {
      this.colorResult = value;
    }));
    new import_obsidian.Setting(contentEl).addButton((btn) => btn.setButtonText("Submit").setCta().onClick(() => {
      this.close();
      this.onSubmit(this.colorResult);
    }));
  }
  onClose() {
    let { contentEl } = this;
    contentEl.empty();
  }
};

// src/rgbConverter.ts
var RGBConverter = class {
  componentToHex(c) {
    let hex = c.toString(16);
    return hex.length == 1 ? "0" + hex : hex;
  }
  rgbToHex(rgb) {
    let substr = rgb.substring(4, rgb.length - 1);
    let rgbArr = substr.split(",");
    let hexStr = "#";
    for (let i = 0; i < 3; i++) {
      hexStr += this.componentToHex(parseInt(rgbArr[i]));
    }
    return hexStr;
  }
};

// src/main.ts
var DEFAULT_COLOR = "#000000";
var DEFAULT_SETTINGS = {
  colorArr: ["#000000", "#000000", "#000000", "#000000", "#000000"]
};
var ColoredFont = class extends import_obsidian2.Plugin {
  async onload() {
    this.curColor = DEFAULT_COLOR;
    this.curIndex = 0;
    let rgbConverter = new RGBConverter();
    await this.loadColorData();
    this.addCommand({
      id: "add-text",
      name: "Add the colored text",
      hotkeys: [],
      editorCallback: (editor, view) => {
        var selection = editor.getSelection();
        editor.replaceSelection(`<font style="color:${this.curColor}">${selection}</font>`);
        const curserEnd = editor.getCursor("to");
        editor.setCursor(curserEnd.line, curserEnd.ch + 1);
      }
    });
    this.addCommand({
      id: "get-color-input",
      name: "Get Color Input",
      hotkeys: [],
      callback: () => {
        new ColorModal(this.app, this.curColor, (result) => {
          this.curColor = result;
          colorDivs[this.curIndex].style.backgroundColor = result;
          this.colorsData.colorArr[this.curIndex] = result;
          this.saveColorData();
        }).open();
      }
    });
    this.addCommand({
      id: "change-color-forward",
      name: "Change the Color Forward",
      hotkeys: [],
      callback: () => {
        this.prevIndex = this.curIndex;
        this.curIndex = this.curIndex == 4 ? 0 : this.curIndex + 1;
        colorDivs[this.prevIndex].style.borderStyle = "none";
        colorDivs[this.curIndex].style.borderStyle = "solid";
        this.curColor = rgbConverter.rgbToHex(colorDivs[this.curIndex].style.backgroundColor);
      }
    });
    this.addCommand({
      id: "change-color-backwards",
      name: "Change the Color Backwards",
      hotkeys: [],
      callback: () => {
        this.prevIndex = this.curIndex;
        this.curIndex = this.curIndex == 0 ? 4 : this.curIndex - 1;
        colorDivs[this.prevIndex].style.borderStyle = "none";
        colorDivs[this.curIndex].style.borderStyle = "solid";
        this.curColor = rgbConverter.rgbToHex(colorDivs[this.curIndex].style.backgroundColor);
      }
    });
    var statusBarColor = this.addStatusBarItem();
    const colorDivs = [];
    for (let i = 0; i < 5; i++) {
      var colorText = statusBarColor.createEl("div", { cls: "status-color" });
      colorText.style.backgroundColor = this.colorsData.colorArr[i];
      colorDivs.push(colorText);
    }
    colorDivs[0].style.borderStyle = "solid";
  }
  async loadColorData() {
    this.colorsData = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }
  async saveColorData() {
    await this.saveData(this.colorsData);
  }
};