// dateTimeUtils.js

function getCurrentDateTimeInNepal() {
    const now = new Date();
    const timeZone = 'Asia/Kathmandu';
    const options = {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    };
  
    const nepaliDateTime = new Intl.DateTimeFormat('en-US', {
      ...options,
      timeZone,
    }).format(now);
  
    const [datePart, timePart] = nepaliDateTime.split(', ');
    const [month, day, year] = datePart.split('/');
    const [hour, minute, second] = timePart.split(':');
  
    const isoDateTime = `${year}-${month}-${day}T${hour}:${minute}:${second}`;
    return isoDateTime;
  }
  
  module.exports = {
    getCurrentDateTimeInNepal,
  };
  