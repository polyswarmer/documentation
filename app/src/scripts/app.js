import MainController from './controllers/main-controller';

$(document).ready(() => {
  const mainController = new MainController();
  mainController.init();
});
