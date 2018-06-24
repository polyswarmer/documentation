export default class Dropdown {
  constructor() {
    this.classText = {
      namespace: 'dropdown',
      dropdownToggles: '.js-dropdown',
      dropdown: '.m-dropdown',
      isOpen: 'is-dropdown-open',
      isFocused: 'is-focused'
    };
  }

  cacheElements() {
    return new Promise((resolve, reject) => {
      const { classText } = this;

      this.$$ = { dropdownToggles: $(classText.dropdownToggles) };

      if (!this.$$.dropdownToggles.length) {
        reject();
      } else {
        this.$$.document = $(document);
        this.$$.dropdowns = $(classText.dropdown);
        resolve();
      }
    });
  }

  bindings() {
    const { $$, classText } = this;

    // Toggle dropdowns
    $$.dropdownToggles.on(`click.${classText.namespace}`, e => {
      const $this = $(e.currentTarget);
      const isOpen = $this.hasClass(classText.isOpen);
      if (!isOpen) {
        $$.dropdownToggles.removeClass(classText.isOpen);
        $this.addClass(classText.isOpen);
      } else {
        $this.removeClass(classText.isOpen);
      }
    });

    // Focus states
    $$.dropdowns.on(`focusin.${classText.namespace}`, e => {
      $(e.currentTarget).addClass(classText.isFocused);
    });

    $$.dropdowns.on(`focusout.${classText.namespace}`, e => {
      $(e.currentTarget).removeClass(classText.isFocused);
      $$.dropdownToggles.removeClass(classText.isOpen);
    });

    // Esc key
    $$.document.on(`keyup.${classText.namespace}`, e => {
      if (e.keyCode === 27) {
        $$.dropdownToggles.removeClass(classText.isOpen);
      }
    });

    // Close when you click out
    $$.document.on(`click.${classText.namespace}`, () => {
      $$.dropdownToggles.removeClass(classText.isOpen);
    });

    $$.dropdownToggles.on(`click.${classText.namespace}`, e => {
      e.stopPropagation();
    });

    $$.dropdowns.on(`click.${classText.namespace}`, e => {
      e.stopPropagation();
    });
  }

  init() {
    this.cacheElements().then(() => this.bindings(), () => {});
  }
}
