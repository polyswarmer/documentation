export default class SidebarNav {
  constructor() {
    this.classText = {
      namespace: 'sidebarNav',
      wrap: '#js-sidebar-nav-wrap',
      nav: '#js-sidebar-nav',
      list: '#js-sidebar-nav-list',
      heading: 'h2',
      isFixed: 'is-fixed',
      isActive: 'is-active'
    };
    this.positions = {
      wrapTop: 0,
      wrapBottom: 0,
      marginTop: 0,
      atBottom: false
    };
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
        this.$$.sections = this.$$.wrap.find(classText.heading);
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

  handleResize() {
    const { $$, classText } = this;
    this.positions.wrapTop = $$.wrap.offset().top;
    this.positions.wrapBottom = $$.wrap.offset().top + $$.wrap.outerHeight() - $$.window.height();
    this.positions.marginTop = parseInt(
      $(classText.heading)
        .first()
        .css('marginTop')
        .replace('px', ''),
      10
    );
  }

  handleScroll() {
    const { $$, positions, classText } = this;
    const scrollPosition = $$.document.scrollTop();

    // Switch nav to fixed position
    if (scrollPosition >= positions.wrapTop && positions.wrapBottom > scrollPosition) {
      $$.list.addClass(classText.isFixed);
    } else {
      $$.list.removeClass(classText.isFixed);
    }

    // Set top property if at the bottom
    if (positions.wrapBottom <= scrollPosition && !positions.atBottom) {
      positions.atBottom = true;
      $$.list.css('top', scrollPosition - positions.wrapTop);
    } else if (positions.wrapBottom > scrollPosition && positions.atBottom) {
      positions.atBottom = false;
      $$.list.css('top', 0);
    }

    // Track scroll position of sections
    $$.sections.each((i, el) => {
      const $el = $(el);
      const id = $el.attr('id');
      // Account for margin due to collapsing
      const elementPosition = $el.offset().top - positions.marginTop;
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
    $$.window.on(`resize.${classText.namespace}`, () => this.handleResize()).trigger(`resize.${classText.namespace}`);
    $$.window.on(`scroll.${classText.namespace}`, () => this.handleScroll()).trigger(`scroll.${classText.namespace}`);
  }

  init() {
    Promise.all([this.cacheElements(), this.createElements()]).then(() => this.bindings(), () => {});
  }
}
