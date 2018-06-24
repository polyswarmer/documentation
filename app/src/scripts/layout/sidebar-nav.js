export default class SidebarNav {
  constructor() {
    this.classText = {
      namespace: 'sidebarNav',
      wrap: '#js-sidebar-nav-wrap',
      nav: '#js-sidebar-nav',
      list: '#js-sidebar-nav-list',
      isFixed: 'is-fixed',
      isActive: 'is-active'
    };
    this.atBottom = false;
  }

  cacheElements() {
    return new Promise((resolve, reject) => {
      const { classText } = this;

      this.$$ = { wrap: $(classText.wrap) };

      if (!this.$$.wrap.length) {
        reject();
      } else {
        this.$$.window = $(window);
        this.$$.document = $(document);
        this.$$.sections = this.$$.wrap.find('h2');
        this.$$.nav = this.$$.wrap.find(classText.nav);
        this.$$.list = $(classText.list);
        resolve();
      }
    });
  }

  createElements() {
    return new Promise((resolve, reject) => {
      const { $$ } = this;

      if ($$.sections.length <= 1) {
        reject();
      } else {
        $$.sections.each((i, el) => {
          const $el = $(el);
          const text = $el.text();
          const id = $el.attr('id');

          $$.list.append(`
            <li>
              <a href="#${id}">${text}</a>
            </li>
          `);
        });
        resolve();
      }
    });
  }

  handleScroll() {
    const { $$, classText } = this;
    const scrollPosition = $$.document.scrollTop();
    const wrapTop = $$.wrap.offset().top;
    const wrapBottom = $$.wrap.offset().top + $$.wrap.outerHeight() - $$.window.height();

    // Switch nav to fixed position
    if (scrollPosition >= wrapTop && wrapBottom > scrollPosition) {
      $$.list.addClass(classText.isFixed);
    } else {
      $$.list.removeClass(classText.isFixed);
    }

    // Set top property if at the bottom
    if (wrapBottom <= scrollPosition && !this.atBottom) {
      this.atBottom = true;
      $$.list.css('top', scrollPosition - wrapTop);
    } else if (wrapBottom > scrollPosition && this.atBottom) {
      this.atBottom = false;
      $$.list.css('top', 0);
    }

    // Track scroll position of sections
    $$.sections.each((i, el) => {
      const $el = $(el);
      const id = $el.attr('id');
      // Account for margin due to collapsing
      const margin = parseInt($el.css('marginTop').replace('px', ''), 10);
      const elementPosition = $el.offset().top - margin;

      // Make viewable section active
      if (elementPosition <= scrollPosition) {
        $$.list.find('li').removeClass(classText.isActive);
        $$.list
          .find(`a[href="#${id}"]`)
          .parent()
          .addClass(classText.isActive);
      }
    });
  }

  bindings() {
    const { $$, classText } = this;
    $$.window.on(`scroll.${classText.namespace}`, () => this.handleScroll()).trigger(`scroll.${classText.namespace}`);
  }

  init() {
    Promise.all([this.cacheElements(), this.createElements()]).then(() => this.bindings(), () => {});
  }
}
