'use strict';

var lodash = angular.module('lodash', []);
lodash.factory('_', function () {
  return window._;
});

var resultMap = ['secure', 'unknown', 'timeout', 'connectionRefused',
                    'vulnerable'];

var stateStyleMap = {
  'secure': 'success',
  'connectionRefused': 'info',
  'timeout': 'warning',
  'vulnerable': 'danger',
  'unknown': 'active'
};

angular.module('angularApp', ['lodash', 'ngRoute', 'ngResource'])
  .config(function ($routeProvider) {
    $routeProvider
      .when('/', {
        templateUrl: 'views/main.html',
        controller: 'MainCtrl'
      })
      .otherwise({
        redirectTo: '/'
      });
  })
  .factory('Targets', function ($resource) {
    return $resource('api/host', {}, {
      query: {method: 'GET', isArray: true}
    });
  })
  .controller('MainCtrl', ['$scope', '$timeout', 'Targets',
    function ($scope, $timeout, Targets) {
      $scope.hosts = [];
      $scope.tFilter = 'vulnerable';
      $scope.stats = {
        state: {}
      };

      (function tick() {
        $scope.hosts = Targets.query(function () {
          _.each($scope.hosts, function (item, index, list) {
            if (typeof item.State === 'number') {
              var friendlyState = resultMap[item.State];
              list[index].State = friendlyState;
              list[index].cssClass = stateStyleMap[friendlyState];
            }
          });
          $scope.stats.host_count = $scope.hosts.length;
          $scope.stats.scanned_count = $scope.stats.host_count -
            _.where($scope.hosts, { 'LastChecked': null }).length;
          $scope.stats.state.secure = _.where($scope.hosts, { 'State': 'secure' }).length;
          $scope.stats.state.unknown = _.where($scope.hosts, { 'State': 'unknown' }).length;
          $scope.stats.state.timeout = _.where($scope.hosts, { 'State': 'timeout' }).length;
          $scope.stats.state.connectionRefused = _.where($scope.hosts, { 'State': 'connectionRefused' }).length;
          $scope.stats.state.vulnerable = _.where($scope.hosts, { 'State': 'vulnerable' }).length;
          $timeout(tick, 1000);
        });
      })();
    }]);