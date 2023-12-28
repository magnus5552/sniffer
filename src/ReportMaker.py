class ReportMaker:
    @staticmethod
    def make_report(data: dict, start_time, end_time, path):
        # Create the HTML file
        with open(path, 'w') as file:
            # Write the start_time at the beginning of the file
            file.write(start_time + '\n')

            # Write the table header
            file.write('<table>\n')
            file.write('<tr>\n')
            file.write('<th>Host</th>\n')
            file.write('<th>Packets Size</th>\n')
            file.write('<th>Packets Count</th>\n')
            file.write('</tr>\n')

            # Write the data for each host
            for host, values in data.items():
                file.write('<tr>\n')
                file.write('<td>{}</td>\n'.format(host))
                file.write('<td>{}</td>\n'.format(values[0]))
                file.write('<td>{}</td>\n'.format(values[1]))
                file.write('</tr>\n')

            # Close the table and write the end_time at the end of the file
            file.write('</table>\n')
            file.write(end_time + '\n')
