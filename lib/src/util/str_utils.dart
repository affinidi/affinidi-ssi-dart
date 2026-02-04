// FIXME : Remove this file.
// THIS MODULE IS EXPERIMENTAL AND INCOMPLETE. THE API MAY CHANGE IN THE FUTURE. USE WITH CAUTION.
// THIS MODULE IS INCOMPLETE AND NOT YET USED.

List<String> split(String text, Pattern pattern, int partCount) {
  // Function to split a string by pattern with a limit on number of parts
  // If partCount is less than or equal to 0,
  // or if the number of parts is less than or equal to partCount, return all parts
  var parts = text.split(pattern);
  if (partCount <= 0 || parts.length <= partCount) {
    return parts;
  }
  var result = <String>[];
  for (var i = 0; i < partCount - 1; i++) {
    result.add(parts[i]);
  }
  result.add(parts.sublist(partCount - 1).join(''));
  return result;
}
