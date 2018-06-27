export default class SidebarNav {
  constructor() {
    this.classText = {
      namespace: 'sidebarNav',
      section: '#js-sidebar-nav-section',
      nav: '#js-sidebar-nav',
      headings: 'h2',
      subheadings: 'h3',
      parentClass: 'js-sidebar-nav-parent l-sidebar-nav__link-parent',
      childClass: 'js-sidebar-nav-child l-sidebar-nav__link-child',
      isFixed: 'is-fixed',
      isAbsolute: 'is-absolute',
      isActive: 'is-active'
    };

    this.handlers = {
      resize: `resize.${this.classText.namespace}`,
      scroll: `scroll.${this.classText.namespace}`
    };

    this.positions = {};

    this.headingOffsets = {};
  }

  cacheElements() {
    return new Promise((resolve, reject) => {
      const { classText } = this;

      this.$$ = { section: $(classText.section) };

      if (!this.$$.section.length) {
        reject();
      } else {
        this.$$.window = $(window);
        this.$$.nav = $(classText.nav);
        this.$$.headings = this.$$.section.find(`${classText.headings},${classText.subheadings}`);
        resolve();
      }
    });
  }

  createListItems() {
    return new Promise((resolve, reject) => {
      const { $$, classText } = this;

      if ($$.headings.length < 2) {
        reject();
      } else {
        const headings = [];
        let headingCount = -1;

        // Generate list
        $$.headings.each((i, el) => {
          const $el = $(el);
          const id = $el.attr('id');
          const text = $el.text();
          const isHeading = $el.prop('tagName') === classText.headings.toUpperCase();
          if (isHeading) {
            headings.push($(`<li><a href="#${id}" class="${classText.parentClass}">${text}</a></li>`));
            headingCount++;
          } else {
            if (!headings[headingCount].find('ul').length) {
              headings[headingCount].append('<ul></ul>');
            }
            headings[headingCount]
              .find('ul')
              .append(`<li><a href="#${id}" class="${classText.childClass}">${text}</a></li>`);
          }
        });

        // Append list to DOM
        const $ul = $('<ul></ul>');
        $ul.append(headings);
        $$.nav.append($ul);

        resolve();
      }
    });
  }

  setAffixPositions() {
    const { $$ } = this;
    this.positions.sectionTop = $$.section.offset().top;
    this.positions.sectionHeight = $$.section.outerHeight();
    this.positions.sectionBottom = this.positions.sectionTop + this.positions.sectionHeight;
    this.positions.navHeight = $$.nav.outerHeight();
    this.positions.navBottom = this.positions.sectionBottom - this.positions.navHeight;
    this.positions.navBottomPlacement = this.positions.navBottom - this.positions.sectionTop;
    this.positions.isFixed = false;
    this.positions.atBottom = false;
  }

  setScrollSpyPositions() {
    const { $$ } = this;
    $$.headings.each((i, el) => {
      const $el = $(el);
      const id = $el.attr('id');
      const { top } = $el.offset();
      this.headingOffsets[top] = `#${id}`;
    });
    console.log(this.headingOffsets);
  }

  affix() {
    const { $$, classText, positions } = this;

    const scrollPosition = $$.window.scrollTop();

    // Above top
    if (scrollPosition < positions.sectionTop && positions.isFixed && !positions.atBottom) {
      $$.nav.removeClass(classText.isFixed);
      this.positions.isFixed = false;

      // Passed top
    } else if (scrollPosition >= positions.sectionTop && !positions.isFixed && !positions.atBottom) {
      $$.nav.addClass(classText.isFixed);
      this.positions.isFixed = true;

      // Above bottom
    } else if (scrollPosition < positions.navBottom && !positions.isFixed && positions.atBottom) {
      $$.nav
        .addClass(classText.isFixed)
        .removeClass(classText.isAbsolute)
        .css('top', '');
      this.positions.isFixed = true;
      this.positions.atBottom = false;

      // Passed bottom
    } else if (scrollPosition >= positions.navBottom && positions.isFixed && !positions.atBottom) {
      $$.nav
        .removeClass(classText.isFixed)
        .addClass(classText.isAbsolute)
        .css('top', `${positions.navBottomPlacement}px`);
      this.positions.isFixed = false;
      this.positions.atBottom = true;
    }
  }

  // scrollspy() {}

  // onResize() {}

  // onScroll() {}

  bindings() {
    const { $$, handlers } = this;

    // Set positions on load
    $(window).on('load', () => this.setPositions());

    $$.window.on(handlers.resize, _.debounce(this.setPositions.bind(this), 150));
    $$.window.on(handlers.scroll, () => this.affix());
  }

  init() {
    Promise.all([this.cacheElements(), this.createListItems()]).then(() => this.bindings(), () => {});
  }
}

// // Scrollspy
// $(window).on('scroll.spy', () => {
//   const scrollPosition = $(window).scrollTop();

//   for (offset in headingOffsets) {
//     if (scrollPosition >= parseInt(offset, 10)) {
//       const id = headingOffsets[offset];
//       const $link = $nav.find(`a[href="${id}"]`);
//       $links.removeClass('is-active');
//       $link.addClass('is-active');
//       if ($link.hasClass('nav-link--child')) {
//         $link
//           .parent()
//           .parent()
//           .parent()
//           .find('.nav-link--parent')
//           .addClass('is-active');
//       }
//     }
//   }
// });
