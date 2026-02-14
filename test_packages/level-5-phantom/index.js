// Legitimate-looking main file
module.exports = {
  load: function(config) {
    return { status: 'ok', config };
  },
  
  process: function(data) {
    return { processed: true, data };
  }
};