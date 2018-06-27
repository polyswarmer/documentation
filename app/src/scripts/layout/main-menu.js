export default class MainMenu {
  constructor() {
    this.classText = {
      namespace: 'mainMenu',
      menu: '#js-main-menu',
      toggle: '#js-main-menu-toggle',
      isOpen: 'is-menu-open'
    };
  }

  cacheElements() {
    return new Promise((resolve, reject) => {
      const { classText } = this;

      this.$$ = { menu: $(classText.menu) };

      if (!this.$$.menu.length) {
        reject();
      } else {
        this.$$.window = $(window);
        this.$$.document = $(document);
        this.$$.html = $('html');
        this.$$.toggle = this.$$.menu.find(classText.toggle);
        resolve();
      }
    });
  }

  bindings() {
    const { $$, classText } = this;

    $$.toggle.on(`click.${classText.namespace}`, e => {
      e.preventDefault();
      $$.html.toggleClass(classText.isOpen);
    });

    // Esc key
    $$.document.on(`keyup.${classText.namespace}`, e => {
      if (e.keyCode === 27) {
        $$.html.removeClass(classText.isOpen);
      }
    });

    $$.window.on(`resize.${classText.namespace}`, () => {
      $$.html.removeClass(classText.isOpen);
    });
  }

  init() {
    this.cacheElements().then(() => this.bindings(), () => {});
  }
}
