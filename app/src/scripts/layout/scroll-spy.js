export default class ScrollSpy {
  constructor() {
    this.classText = {
      namespace: 'scrollSpy',
      page: '#js-scroll-spy',
      list: '#js-scroll-spy-list',
      isActive: 'is-active'
    };
  }

  cacheElements() {
    return new Promise((resolve, reject) => {
      const { classText } = this;

      this.$$ = { page: $(classText.page) };

      if (!this.$$.page.length) {
        reject();
      } else {
        this.$$.window = $(window);
        this.$$.document = $(document);
        this.$$.sections = this.$$.page.find('h2');
        this.$$.list = $(classText.list);
        console.log('cache');
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

          // Use h2 text to create sections IDs
          const text = $el.text();
          const id = text
            .toLowerCase()
            .replace(/[^\w\s-]/g, '')
            .replace(/\s/g, '-');

          // Add section IDs to h2 tags
          $el.attr('id', id);

          $$.list.append(`
            <li>
              <a href="#${id}">${text}</a>
            </li>
          `);
        });
        console.log('create');
        resolve();
      }
    });
  }

  bindings() {
    // const { $$, classText } = this;
    // $$.window.on(`scroll.${classText.namespace}`, () => {
    //   const scrollPosition = $document.scrollTop();
    //   $sections.each((i, el) => {
    //     const $el = $(el);
    //     const id = $el.attr('id');
    //     const elementPosition = $el.offset().top;
    //     if (elementPosition <= scrollPosition) {
    //       $links.removeClass(classText.isActive);
    //       $(`a[href="#${id}"]`).addClass(classText.isActive);
    //     }
    //   });
    // });
    console.log('bindings');
    console.log(this);
  }

  init() {
    Promise.all([this.cacheElements(), this.createElements()]).then(() => this.bindings(), () => {});
  }
}
