#
# $Id$
#

require 'json'
require 'rex/text/table'
require 'getoptlong'
require 'tts'

module Msf

###
#
# This plugin provides voice command script management for voice assistants.
#
# author Jonathan Stregger
# email: jon.stregger@gmail.com
# github: github.com/JonathanStregger
#
# This plugin requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# $Revision$
#
###

class Plugin::MsfVC < Msf::Plugin
  ###
  #
  # This class implements a console command dispatcher.
  # Adds vc_list, vc_details, vc_script, and vc_help to the console.
  #
  ###
  class MsfvcCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    #
    # The dispatcher's name
    #
    def name
      'MsfVC'
    end

    #
    # Initialize the command dispatcher.
    # Gets the data from voice-commands.json in the data/wordlists directory.
    #
    # @scripts is a list of voice command scripts generated with the plugin.
    #
    def initialize(driver)
      super

      @vc_data = VCData.new('voice-commands.json')
      @scripts = []
    end

    #
    # Returns a hash of the commands supported by the command dispatcher
    #
    def commands
      {
        'vc_list'     => 'List available voice commands',
        'vc_details'  => 'Display details for a voice command by id or command text',
        'vc_script'   => 'Create or add to a voice command script.',
        'vc_tts'      => 'Text-to-speech for a script.',
        'vc_help'     => 'Display msfvc help'
      }
    end

    #
    # The Text to Speech command.
    #
    #   A voice command script, such as one made with the vc_script command,
    #   can be converted to voice using Google's translation api via the tts
    #   gem.
    #
    def cmd_vc_tts(*args)
      begin
        # Store environment arguments when get opt uses the args that will
        # be temporarily stored in ARGV
        env_args = ARGV.clone
        ARGV.clear
        args.each { |arg| ARGV << arg }
  
        #
        # Recognized options are:
        #   Help menu with -h
        #   Script identifier -s <script name>
        #   Specify filename -f <filename>
        #
        opts = GetoptLong.new(
          ['--help', '-h', GetoptLong::NO_ARGUMENT],
          ['--script', '-s', GetoptLong::REQUIRED_ARGUMENT],
          ['--filename', '-f', GetoptLong::OPTIONAL_ARGUMENT]
        )

        script = ''
        filename = ''
        begin
          opts.each do |opt, arg|
            case opt
            when '--help'
              return usage_vc_tts
            when '--script'
              script = arg
            when '--filename'
              filename = arg unless arg.empty?
            end
          end
        rescue GetoptLong::Error
          return
        end
        
        return print_error('Script name required.') if script.empty?
        
        # Default filename will be the script name if no filename is provided
        filename = script.dup if filename.empty?
        tts_script = get_script(script)
        begin
          print_status('Contacting Google Translation Service')
          write_path = tts_script.to_af(filename)
          return print_error("Could not find #{script} script. Cannot perform TTS on script.") unless tts_script
          print_status("#{script} script written as speech to #{write_path}")
        rescue IOError => e
          print_error("Could not save #{script} script as audio. #{e}")
        rescue ArgumentError => e
          print_error(e)
        rescue NotImplementedError => e
          print_error(e)
        end
      ensure
        # Restore environment arguments
        ARGV.clear
        env_args.each { |arg| ARGV << arg }
      end
    end

    #
    # The help display for the vc_tts command.
    #
    def usage_vc_tts
      tbl = Rex::Text::Table.new(
        'Indent'        => 4,
        'Header'        => 'Text-to-speech Commands help',
        'Columns'       =>
        [
          'Option',
          'Description',
          'Example'
        ]
      )
      tbl << ['-s, --script', 'The label for the script to convert to speech.', 'vc_tts -s example']
      tbl << ['-f, --filename', 'Specify the filename for the tts audio file.', 'vc_tts -s example -f attack1.mp3']
      tbl << ['-h, --help', 'Show this help message', 'vc_tts --help']
      print("\n#{tbl.to_s}\n")
    end

    #
    # The Voice Command Script command.
    #   Scripts can be created for a voice assistant from the loaded voice
    #   command data file. These scripts can be saved to file in json format
    #   or given to the vc_tts command for saving as an mp3 audio file.
    #
    def cmd_vc_script(*args)
      begin
        # Store environment arguments when get opt uses the args that will
        # be temporarily stored in ARGV
        env_args = ARGV.clone
        ARGV.clear
        args.each { |arg| ARGV << arg }
  
        #
        # Recognized options are:
        #   Help menu with -h
        #   Assistant for script with -a <identifier>
        #   Id of command to add to script with -i <number>
        #   Script identifier with -s <identifier>
        #   Display the script identified with -d
        #   Remove a command by its place in the script with -r <number>
        #   Fill the next wildcard in the current command with -f
        #     Must be used with either -i for a new command or with -m for
        #     modifying an existing command.
        #   Write the script to a json file with -w <optional filename>
        #   Load a script from a json file with -l <filename>
        #   Sanitize the script to make it useable by tts with -z
        #   Set a custom activator word/phrase with -t
        #
        opts = GetoptLong.new(
          ['--help', '-h', GetoptLong::NO_ARGUMENT],
          ['--assistant', '-a', GetoptLong::REQUIRED_ARGUMENT],
          ['--id', '-i', GetoptLong::REQUIRED_ARGUMENT],
          ['--script', '-s', GetoptLong::REQUIRED_ARGUMENT],
          ['--display', '-d', GetoptLong::NO_ARGUMENT],
          ['--remove', '-r', GetoptLong::REQUIRED_ARGUMENT],
          ['--fill', '-f', GetoptLong::REQUIRED_ARGUMENT],
          ['--modify', '-m', GetoptLong::REQUIRED_ARGUMENT],
          ['--write', '-w', GetoptLong::OPTIONAL_ARGUMENT],
          ['--load', '-l', GetoptLong::REQUIRED_ARGUMENT],
          ['--sanitize', '-z', GetoptLong::NO_ARGUMENT],
          ['--activator', '-t', GetoptLong::REQUIRED_ARGUMENT],
          ['--cmd-spacing', '-c', GetoptLong::REQUIRED_ARGUMENT]
        )
        
        assistant = ''  # Script assistant
        activator = ''  # Custom activator word/phrase
        script = ''     # Script identifier
        fill = []       # List of wildcard fill values
        index = -1      # Id of script to add or index of script to remove/modify
        filename = ''   # Filename to write to or load from
        spacing = nil   # Silence spacing between commands
        options = ''    # Selected options
        begin
          opts.each do |opt, arg|
            case opt
            when '--help'
              usage_vc_script
              return
            when '--assistant'
              begin
                assistant = @vc_data.get_assistant(arg)
                options << 'a'
              rescue ArgumentError => e
                print_error(e)
                return
              end
            when '--script'
              script = arg
            when '--display'
              options << 'd'
            when '--remove'
              return print_error('Choose one of add, modify, or remove.') if options.include?('i') || options.include?('m')
              begin
                index = Integer(arg)
                options << 'r'
              rescue ArgumentError
                return print_error('An integer is required for remove index.')
              end
            when '--fill'
              fill << arg
              options << 'f'
            when '--id'
              return print_error('Choose one of add, modify, or remove.') if options.include?('m') || options.include?('r')
              begin
                index = Integer(arg)
                options << 'i'
              rescue ArgumentError
                return print_error('An integer is required for id.')
              end
            when '--modify'
              return print_error('Choose one of add, modify, or remove.') if options.include?('i') || options.include?('r')
              begin
                index = Integer(arg)
                options << 'm'
              rescue ArgumentError
                return print_error('An integer is required for modify index.')
              end
            when '--write'
              options << 'w'
              filename = arg if arg
            when '--load'
              return load_from_file(arg)
            when '--sanitize'
              options << 'z'
            when '--activator'
              options << 't'
              activator = arg
            when '--cmd-spacing'
              options <<'c'
              spacing = arg
            end
          end
        rescue GetoptLong::Error
          return
        end

        # Check for operable option conditions
        return print_error('A script name is required to start or modify a script.') if script.empty?
        return print_error('No operable options received.') if options.empty?
        
        # Process options remove, modify or add
        begin
          if options.include?('r')
            remove_from_script(script, index)
            print_status("Command successfully removed from #{script} script at index #{index}.")
          elsif options.include?('m')
            mod_script(script, index, fill)
            print_status("Command successfully modified in #{script} script at index #{index}.")
          elsif options.include?('i')
            raise ArgumentError.new('A voice assistant must be specified with the -a or --assistant option or ? to list available voice assistants') if assistant.empty?
            raise ArgumentError.new('A positive id is required to add voice commands to scripts.') if index < 1
            
            add_to_script(script, assistant, index, fill)
            print_status("Command successfully added to #{script}.")
          end
        rescue ArgumentError => e
          print_error(e)
        end
        
        # All other options may be used together
        set_silence(script, spacing) if options.include?('c')
        get_script(script).activator = activator if options.include?('t')
        sanitize_script(script) if options.include?('z')
        display_script(script) if options.include?('d')
        write_script(script, filename) if options.include?('w')
      ensure
        # Restore environment arguments
        ARGV.clear
        env_args.each { |arg| ARGV << arg }
      end
    end

    #
    # The help prompt for the vc_script command.
    #
    def usage_vc_script
      tbl = Rex::Text::Table.new(
        'Indent'        => 4,
        'Header'        => 'Script Voice Commands help',
        'Columns'       =>
        [
          'Option',
          'Description',
          'Example'
        ]
      )
      tbl << ['-a, --assistant', 'The voice assistant to display.', 'vc_script -a Google -i 3 -s example']
      tbl << ['-i, --id', 'The id of the voice command to add/edit/delete in the script', 'vc_script -i 4 -a Siri -s example']
      tbl << ['-d, --display', 'Display the script in its current form', 'vc_script -d -s example']
      tbl << ['-s, --script', 'The label for the script to create/modify.', 'vc_script -s example -i 4 -a Alexa']
      tbl << ['-r, --remove', 'Remove a voice command from the script given a script index.', 'vc_script -s example -r 0']
      tbl << ['-f, --fill', 'Fill a wildcard slot with the given argument.', 'vc_script -s example -a Siri -i 5 -f "Jon Doe" -f "this is a test"']
      tbl << ['-m, --modify', "Modify a voice command in the script given the script index.", 'vc_script -s example -m 2']
      tbl << ['-w, --write', 'Write the script to file. Default name is the script name, but a filename can be specified.', 'vc_script -s example -w script.json']
      tbl << ['-l, --load', 'Load a script from the specified json file in the data/msfvc directory.', 'vc_script -l script.json']
      tbl << ['-z, --sanitize', 'Sanitize all commands in the script.', "vc_script -s example -z\n"]
      tbl << ['-c, --cmd-spacing','Set the amount of silence between scripts in ms or by string','vc_script -s example -c 1-minute-3-seconds-250-milliseconds']
      tbl << ['-c, --cmd-spacing','','vc_script -s example -c 1500']
      tbl << ['Example','vc_script -s Test -i 5 -f "Jon Doe" -f "this is a test" -z -d -w -c 1500', '']
      tbl << ['-h, --help', 'Show this help message', 'vc_script --help']
      print("\n#{tbl.to_s}\n")
    end

    def cmd_vc_list(*args)
      begin
        # Store environment arguments when get opt uses the args that will
        # be temporarily stored in ARGV
        env_args = ARGV.clone
        ARGV.clear
        args.each { |arg| ARGV << arg }
  
        opts = GetoptLong.new(
          ['--help', '-h', GetoptLong::NO_ARGUMENT],
          ['--assistant', '-a', GetoptLong::REQUIRED_ARGUMENT],
          ['--category', '-c', GetoptLong::REQUIRED_ARGUMENT],
          ['--search', '-s', GetoptLong::REQUIRED_ARGUMENT],
          ['--verbose', '-v', GetoptLong::NO_ARGUMENT]
        )
        
        categories = []
        search = []
        assistant = ''
        verbose = 0
        begin
          opts.each do |opt, arg|
            case opt
            when '--help'
              usage_vc_list
              return
            when '--category'
              categories << arg.downcase
            when '--search'
              search << arg.downcase
            when '--assistant'
              begin
                assistant = @vc_data.get_assistant(arg)
              rescue ArgumentError => e
                print_error(e)
                return
              end
            when '--verbose'
              verbose = 1
            end
          end
        rescue GetoptLong::Error
          return
        end
        
        return print_error('A voice assistant must be specified with the -a or --assistant option or ? to list available voice assistants') if assistant.empty?

        begin
          if verbose == 1
            print_line("\n#{@vc_data.to_s_verbose(assistant, categories, search)}")
          else
            print_line("\n#{@vc_data.to_s(assistant, categories, search)}")
          end
        rescue ArgumentError => e
          print_error(e)
        end
      ensure
        # Restore environment arguments
        ARGV.clear
        env_args.each { |arg| ARGV << arg }
      end
    end
    
    def usage_vc_list
      tbl = Rex::Text::Table.new(
        'Indent'        => 4,
        'Header'        => 'List Voice Commands help',
        'Columns'       =>
        [
          'Option',
          'Description',
          'Example'
        ]
      )
      tbl << ['-a, --assistant', 'Required. The voice assistant to display.', 'vc_list -a Google']
      tbl << ['-c, --category', 'Add a category to filter displayed voice commands. Repeated for multiple categories. ? to list supported voice assistants', 'vc_list -a Apple -c travel -c navigation']
      tbl << ['-s, --search', 'Search for commands with some or all of the command text.', 'vc_list -a Google -s "voice mail"']
      tbl << ['-v, --verbose','Display verbose.', 'vc_list -a Siri -v']
      tbl << ['-h, --help', 'Show this help message', 'vc_list --help']
      print("\n#{tbl.to_s}\n")
    end
    
    def cmd_vc_details(*args)
      begin
        # Store environment arguments when get opt uses the args that will
        # be temporarily stored in ARGV
        env_args = ARGV.clone
        ARGV.clear
        args.each { |arg| ARGV << arg }
  
        opts = GetoptLong.new(
          ['--help', '-h', GetoptLong::NO_ARGUMENT],
          ['--assistant', '-a', GetoptLong::REQUIRED_ARGUMENT],
          ['--id', '-i', GetoptLong::REQUIRED_ARGUMENT],
          ['--search', '-s', GetoptLong::REQUIRED_ARGUMENT]
        )
        
        assistant = ''
        id = -1
        search = []
        begin
          opts.each do |opt, arg|
            case opt
            when '--help'
              usage_vc_details
              return
            when '--assistant'
              begin
                assistant = @vc_data.get_assistant(arg)
              rescue ArgumentError => e
                print_error(e)
                return
              end
            when '--search'
              return print_error('Options -s and -i must not be used together.') if id != -1
              search << arg
            when '--id'
              return print_error('Options -s and -i must not be used together.') unless search.empty?
              begin
                id = Integer(arg)
                return print_error('A positive integer is required for the -i option') if id < 1
              rescue ArgumentError
                return print_error('An integer is required for -i option.')
              end
            end
          end
        rescue GetoptLong::Error
          return
        end

        return print_error("Either search or id option required.") if search.empty? && id == -1

        if search.empty? && id != -1
          cmd = @vc_data.find_by_id(assistant, id)
        elsif !search.empty? && id == -1
          cmd = @vc_data.find_by_str(assistant, search)
          unless cmd.nil?
            print_status("Found #{cmd.length} results.") if cmd.length > 2
            cmd = cmd[0]
            assistant = cmd.pop()
          end
        end

        if cmd.nil?
          print_error('No command found')
        else
          print_line("\n#{@vc_data.to_s_details(assistant, cmd)}")
        end
      ensure
        # Restore environment arguments
        ARGV.clear
        env_args.each { |arg| ARGV << arg }
      end
    end

    def usage_vc_details
      tbl = Rex::Text::Table.new(
        'Indent'        => 4,
        'Header'        => 'Voice Command Details help',
        'Columns'       =>
        [
          'Option',
          'Description',
          'Example'
        ]
      )
      tbl << ['-a, --assistant', 'The voice assistant the command belongs to. Required with -i option.', 'vc_details -a Google -i 1']
      tbl << ['-i, --id', 'The id of the command being requested. Requires -a option.', 'vc_details -i 4 -a Siri']
      tbl << ['-s, --search', 'Search for a command with some or all of the command text. Returns first match.', 'vc_details -s "voice mail"']
      tbl << ['-h, --help', 'Show this help message', 'vc_details --help']
      print_line("\n#{tbl.to_s}\nNote: -i and -s may not be used together.\n")
    end

    def cmd_vc_help(*args)
      tbl = Rex::Text::Table.new(
        'Indent'  => 4,
        'Header'        => 'MsfVC Help',
        'Columns'       =>
        [
          'Command',
          'Description'
        ]
      )
      cmds = commands
      cmds.each do |cmd|
        tbl << [cmd.fetch(0), cmd.fetch(1)]
      end
      print_line("\n#{tbl.to_s}\nSee individual commands with -h or --help for details on those commands.\n")
    end

    def display_script(script)
      disp_script = get_script(script)
      unless disp_script
        print_error("#{script} script cannot be displayed. Script not found.")
        return
      end
      print_line("\n#{disp_script.to_s}")
    end

    def remove_from_script(script, index)
      raise ArgumentError.new("#{script} script not found. Cannot remove command from script.") if (rm_script = get_script(script)).nil?

      rm_script.rm(index)
    end

    def add_to_script(script, assistant, id, fill)
      # Add script to scripts list
      add_script = get_script(script) || VCScript.new(script, assistant, @vc_data.get_activator(assistant))
      cmd = @vc_data.find_by_id(assistant, id)
      begin
        vc = VoiceCmd.new(assistant, cmd, fill)
      rescue ArgumentError => e
        return print_error("Could not add command to #{script} script. #{e}")
      end
      add_script.add(vc)
      @scripts << add_script unless get_script(script)
    end

    def mod_script(script, index, fill)
      return print_error("Could not find #{script} script.") if (modify_script = get_script(script)).nil?

      modify_script.mod(index, fill)
    end
    
    def get_script(script)
      @scripts.each do |find|
        if find.name == script
          return find
        end
      end
      nil
    end

    def write_script(script, filename = '')
      write = get_script(script)
      unless write
        print_error("Could not find #{script} script. Script not written to file.")
      else
        begin
          script_path = write.save(filename)
          print_status("#{script} script written to '#{script_path}'.")
          print_error("WARNING: #{script} script contains commands that are not speech safe.") unless write.speech_safe?
        rescue IOError => e
          print_error("#{script} script not written to '#{script_path}'. #{e}")
        rescue SystemCallError => e
          print_error("#{script} script not written to '#{script_path}'. #{e}")
        rescue ArgumentError => e
          print_error(e)
        end
      end
    end

    def load_from_file(filename)
      load_script = VCScript.new('')
      begin
        load_script.read(filename)
        print_status("Script #{load_script.name} loaded from #{filename}.")
        @scripts << load_script
      rescue IOError => e
        print_error("Script not loaded from '#{filename}'. #{e}")
      rescue SystemCallError => e
        print_error("Script not loaded from '#{filename}'. #{e}")
      rescue ArgumentError => e
        print_error(e)
      rescue JSON::ParserError
        print_error("Script not loaded. '#{filename}' could not be parsed as json. Provided file must be json format.")
      end
    end

    def sanitize_script(script)
      dirty_script = get_script(script)
      return print_error("Could not find #{script} script. Script not sanitized") unless dirty_script

      dirty_script.sanitize
      print_status("All commands in #{script} script have been sanitized.")
    end

    def set_silence(script, spacing)
      space_script = get_script(script)
      return print_error("Could not find #{script} script. Script not sanitized") unless space_script

      if space_script.set_spacing(spacing)
        print_status("Spacing for commands in #{script} have been set to #{spacing}.") if spacing.class == String
        print_status("Spacing for commands in #{script} have been set to #{spacing} ms.") if spacing.class == Integer
      else
        print_error()
      end
    end
  end
  
  #
  # The plugin's name.
  #
  def name
    'msfvc'
  end
  
  #
  # A brief description of the MsfVC plugin.
  #
  def desc
    'Provides voice command script management.'
  end
  
  #
  # Constructs a new instance of the plugin and registers the command
  # dispatcher.
  #
  def initialize(framework, opts)
    super
    
    add_console_dispatcher(MsfvcCommandDispatcher)
    
    print_status('Welcome to Voice Command by Jonathan Stregger')
    print_status("%blu                 ___        %clr")
    print_status("%blu      __ _  %red___ %blu/ _/%grn  ______%clr")
    print_status("%blu     /  ' \\%red(_-<%blu/ _/ %grn|/ / __/%clr")
    print_status("%blu    /_/_/_/%red___/%blu_/ %grn|___/\\__/ %clr")
    print_status('')
    print_status('MsfVC Version 1.0 for use with the Metasploit Framework 2020')
    print_status('For a list of commands use vc_help.')
    print_status('')
  end
  
  #
  # Deregister the command dispatcher to cleanup after the plugin.
  #
  def cleanup
    remove_console_dispatcher('MsfVC')
  end
end

class VoiceCmd
  def initialize(assistant = '', cmd = [], fill_args = [])
    raise ArgumentError.new('Assistant and command required for new VoiceCmd.') if (assistant.empty? || cmd.empty?)
    @assistant = assistant
    @id = Integer(cmd[0])
    @cmd = cmd[1]['Command']
    @cat = cmd[1]['Category']
    @fill_notes = cmd[1]['Fill notes'] || 'none'
    @purp = cmd[1]['Purpose'] || 'none'
    @vuln = cmd[1]['Vulnerability'] || 'none'
    @num_fills = @fill_notes.count(',') + 1
    fill(fill_args) unless fill_args.empty?
  end

  attr_reader :assistant, :id, :cmd, :cat, :fill_notes, :purp, :vuln
  
  def fill(args)
    raise(ArgumentError, "More arguments provided than wildcards to replace.") if args.length > @num_fills

    args.each do |arg|
      # replace wildcard with argument
      @cmd = @cmd.sub(/[#\*&@:]/, arg)
      @num_fills -= 1
    end
    @cmd
  end

  def sanitize
    @cmd = @cmd.sub(/(\/\b[a-zA-Z#\*&@:]*\b)|(\/\(.*\))/, '') while @cmd.include?('/')
    @cmd = @cmd.sub(/[\(\)]/, '') while @cmd.include?('(') || @cmd.include?(')')
    @cmd = @cmd.sub(/^\s+/, '')
  end

  def sanitized?
    return !@cmd.match?(/(\/\b[a-zA-Z#\*&@:]*\b)|(\/\(.*\))|[\(\)]/)
  end

  def filled?
    return !@cmd.match?(/[#\*&@:]/)
  end
end

class VCScript
  def initialize(script, assistant = '', activator = '', silence = 0)
    @name = script
    @vc_list = []
    @assistant = assistant
    @activator = activator
    @silence = 0
  end

  attr_reader :name
  attr_accessor :assistant, :activator 

  def set_spacing(spacing)
    @silence = spacing.dup if spacing.class == Integer && spacing > 0
    # Convert to int if only numbers
    if spacing.class == String && spacing !~ /\D/
      @silence = spacing.to_i
    else
      @silence = to_ms(spacing)
    end
    return true if @silence.class == Integer
    false
  end

  def add(add_vc)
    @assistant = add_vc.assistant if @assistant.empty?
    unless @assistant == add_vc.assistant
      raise ArgumentError.new("Script #{@name} is for #{@assistant} voice commands. Recieved incompatible voice command for #{add_vc.assistant}")
    else
      @vc_list << add_vc
    end
  end
  
  def rm(index)
    raise ArgumentError.new("Script #{@name} has no voice commands to remove.") unless @vc_list.length > 0
    raise ArgumentError.new("Index is out of bounds.") if index < 0 || index >= @vc_list.length

    raise ArgumentError.new("Could not delete command at index #{index}.") if (@vc_list.delete_at(index)).nil?
  end

  def mod(index, fill)
    raise ArgumentError.new("Script #{@name} has no voice commands to modify.") unless @vc_list.length > 0
    raise ArgumentError.new("Index is out of bounds.") if index < 0 || index >= @vc_list.length
    
    return @vc_list[index].fill(fill) unless fill.empty?
    
    raise ArgumentError.new("Could not modify command at index #{index}. No fill option received.")
  end

  def index(ind)
    return nil if ind < 0 || ind > @vc_list.length
    @vc_list[ind]
  end

  def get_vc(id)
    @vc_list.each { |find| return find if find.id == id }
    nil
  end

  def speech_safe?
    @vc_list.each { |vc| return false if vc.cmd.match(/[#\*&@:]/) }
    true
  end
  
  def save(filename = '')
    raise ArgumentError.new("'#{@name}' script not saved. No commands in script to save.") unless @vc_list.length > 0
    raise ArgumentError.new("Invalid file location. Enter filename only.") if filename.include?('/') || filename.include?('\\')

    script_hash = {"Script" => @name, "Assistant" => @assistant, "Activator" => @activator }
    cmds = Hash.new
    @vc_list.each do |vc|
      vc.sanitize
      cmds.store(@vc_list.index(vc) + 1,
        {"Id"           => vc.id,
        "Command"       => vc.cmd,
        "Category"      => vc.cat,
        "Fill notes"    => vc.fill_notes,
        "Purpose"       => vc.purp,
        "Vulnerability" => vc.vuln})
    end
    script_hash.store("Commands", cmds)

    filename = @name.dup if filename.empty?
    filename << '.json' unless (filename.include?('.json'))
    script_path = File.join(Msf::Config.data_directory, 'msfvc', filename)
    File.open(script_path, 'w') do |fp|
      fp.write(JSON.pretty_generate(script_hash))
    end
    script_path
  end

  def read(filename)
    raise ArgumentError.new("Invalid file location. Enter filename only.") if filename.include?('/') || filename.include?('\\')
    
    script_path = File.join(Msf::Config.data_directory, 'msfvc', filename)
    script_data = JSON.parse(File.read(script_path))
    @name = script_data['Script']
    @assistant = script_data['Assistant']
    @activator = script_data['Activator']
    
    raise ArgumentError.new("Unable to load script. JSON file does not have required fields for a vc script.") if script_data.nil? || @name.nil? || @assistant.nil?
    
    script_data['Commands'].each do |cmd|
      id = cmd[1]['Id']
      cmd[1].delete('Id')
      load_cmd = [id, cmd[1]]
      @vc_list << VoiceCmd.new(@assistant, load_cmd)
    end
  end

  def sanitize
    @vc_list.each { |vc| vc.sanitize }
  end

  def to_s()
    tbl = Rex::Text::Table.new(
        'Indent'        => 4,
        'Header'        => "Script #{@name} for #{@assistant}",
        'Columns'       =>
        [
          'Index',
          'Id',
          'Command'
        ]
      )
    @vc_list.each { |vc| tbl << [ @vc_list.index(vc), vc.id, vc.cmd ] }
    tbl.to_s
  end

  def tts_safe?
    return false if @vc_list.length == 0
    @vc_list.each { |vc| return false unless vc.sanitized? }
    @vc_list.each { |vc| return false unless vc.filled? }
    true
  end

  def speak
    raise ArgumentError.new("#{@name} script is not tts safe.") unless self.tts_safe?
    raise ArgumentError.new("#{name} does not have an activator assigned.") if @activator.empty?
    # cmd_str = "#{@activator}, "
    # @vc_list.each { |vc| cmd_str << vc.cmd.dup << ', ' }
    raise NotImplementedError.new('Cannot speak.')
  end
  
  def to_af(filename)
    raise ArgumentError.new("#{@name} script is not tts safe.") unless self.tts_safe?
    # Get full path for results audio file 
    filename << '.mp3' unless filename.end_with?('.mp3')
    tts_path = File.join(Msf::Config.data_directory, 'msfvc')
    Dir.mkdir(tts_path) unless Dir.exists?(tts_path)
    tts_path = File.join(tts_path, filename)
    # Get the audio from the text
    cmd_str = @activator.dup << '. '
    cmd_str.to_file('en', tts_path)
    @vc_list.each do |vc|
      add_silence(tts_path)
      cmd_str = vc.cmd.dup << '. '
      cmd_str.to_file('en', tts_path)
    end
    tts_path
  end

  private
  def to_ms(time_str)
    time = 0
    hour = /(?<num>\d+)-hour/.match(time_str)
    hour = hour[:num].to_i unless hour.nil?
    time += hour * 3600000 unless hour.nil?
    min = /(?<num>\d+)-minute/.match(time_str)
    min = min[:num].to_i unless min.nil?
    time += min * 60000 unless min.nil?
    sec = /(?<num>\d+)-second/.match(time_str)
    sec = sec[:num].to_i unless sec.nil?
    time += sec * 1000 unless sec.nil?
    milli = /(?<num>\d+)-millisecond/.match(time_str)
    milli = milli[:num].to_i unless milli.nil?
    time += milli unless milli.nil?
    time
  end
  
  def add_silence(fn)
    time = to_ms(@silence) if @silence.class == String
    time = @silence if @silence.class == Integer
    return if time == 0
    raise ArgumentError.new('Unable to parse silence request') unless time.class == Integer
    raise ArgumentError.new('Maximum supported silence is 5 minutes. Cannot process request.') if time > 300000
    silence_dir = File.join(Msf::Config.data_directory, 'msfvc', 'silence')
    while (time >= 250)
      case time
      when 60000..300000
        silence_fn = '1-minute-of-silence.mp3'
        time -= 60000
      when 15000..59999
        silence_fn = '15-seconds-of-silence.mp3'
        time -= 15000
      when 5000..14999
        silence_fn = '5-seconds-of-silence.mp3'
        time -= 5000
      when 1000..4999
        silence_fn = '1-second-of-silence.mp3'
        time -= 1000
      when 500..999
        silence_fn = '500-milliseconds-of-silence.mp3'
        time -= 500
      when 250..499
        silence_fn = '250-milliseconds-of-silence.mp3'
        time -= 250
      end
      silence_path = File.join(silence_dir, silence_fn)
      `cat "#{silence_path}" >> "#{fn}"`
    end
  end
end

class VCData
  def initialize(filename = 'voice-commands.json')
    vc_json_path = File.join(Msf::Config.data_directory, 'wordlists', filename)
    @vc_data = JSON.parse(File.read(vc_json_path))
  end
  
  def to_s(assistant, category = [], search = [])
    cmds = find_by_str(assistant, search)
    
    tbl = Rex::Text::Table.new(
      'Indent'  => 4,
      'Header'  => "#{assistant} Voice Commands",
      'Columns' =>
      [
        'id',
        'Command',
        'Category'
      ]
    )
    unless cmds.nil?
      cmds.each do |cmd|
        if category.empty? || category.include?(cmd[1]['Category'])
          tbl << [cmd[0],
                  cmd[1]['Command'],
                  cmd[1]['Category']]
        end
      end
    else
      @vc_data[assistant]['Commands'].each do |cmd|
        if category.empty? || category.include?(cmd[1]['Category'])
          tbl << [cmd[0],
                  cmd[1]['Command'],
                  cmd[1]['Category']]
        end
      end
    end
    tbl.to_s
  end

  def to_s_verbose(assistant, category = [], search = [])
    cmds = find_by_str(assistant, search)

    tbl = Rex::Text::Table.new(
      'Indent'  => 4,
      'Header'  => "#{assistant} Voice Commands",
      'Columns' =>
      [
        'id',
        'Command',
        'Category',
      'Fill Notes',
      'Purpose',
      'Vulnerability'
      ]
    )
    unless cmds.nil?
      cmds.each do |cmd|
        if category.empty? || category.include?(cmd[1]['Category'])
          tbl << [cmd[0],
                  cmd[1]['Command'],
                  cmd[1]['Category'],
                  cmd[1]['Fill notes'] || 'none',
                  cmd[1]['Purpose'] || 'none',
                  cmd[1]['Vulnerability'] || 'none']
        end
      end
    else
      @vc_data[assistant]['Commands'].each do |cmd|
        if category.empty? || category.include?(cmd[1]['Category'])
          tbl << [cmd[0],
                  cmd[1]['Command'],
                  cmd[1]['Category'],
                  cmd[1]['Fill notes'] || 'none',
                  cmd[1]['Purpose'] || 'none',
                  cmd[1]['Vulnerability'] || 'none']
        end
      end
    end
    tbl.to_s
  end
  
  def to_s_details(assistant, cmd)
    msg = "#{assistant} Voice Command\n"
    (msg.length - 1).times do
      msg << '='
    end
    msg << "\n\n    Id:\n#{details_line(cmd[0])}\n\n"
    msg << "    Command:\n#{details_line(cmd[1]['Command'])}\n\n"
    msg << "    Fill notes:\n#{details_line(cmd[1]['Fill notes'])}\n\n"
    msg << "    Purpose:\n#{details_line(cmd[1]['Purpose'])}\n\n"
    msg << "    Vulnerability:\n#{details_line(cmd[1]['Vulnerability'])}\n\n"
  end
  
  def find_by_id(assistant, id)
    raise ArgumentError.new('Cannot find by id. Assistant must be specified to search by id.') if assistant.empty?
    
    @vc_data[assistant]['Commands'].each { |cmd| return cmd if cmd[0].to_i == id }
    nil
  end
  
  def find_by_str(assistant, terms = [])
    return nil if terms.empty?

    cmds = []
    terms.each do |search|
    search = search.downcase
      assistant = @vc_data.keys if assistant.empty?
      @vc_data[assistant]['Commands'].each do |cmd|
        if cmd[1]['Command'].include?(search) ||
          check_search(cmd[1]['Category'], search) ||
          check_search(cmd[1]['Fill notes'], search) ||
          check_search(cmd[1]['Purpose'], search) ||
          check_search(cmd[1]['Vulnerability'], search)
          cmd << assistant
          cmds << cmd
        end
      end
    end

    return cmds unless cmds.empty?
    nil
  end
  
  def get_assistant(assistant)
    if assistant == '?'
      supported = "\nSupported voice assistants\n==========================\n"
      supported_vas = @vc_data.keys
      supported_vas.each { |va| supported << "    #{va}\n" }
      raise ArgumentError.new(supported)
    end

    test_case = assistant.downcase.sub(/^hey /,'').sub(/^ok /, '')
    @vc_data.keys.each { |va| return va if va.downcase.include?(test_case.downcase) }
    
    raise ArgumentError.new("#{assistant} is not a supported voice assistant.")
  end

  def get_activator(assistant)
    @vc_data.keys.each { |va| return @vc_data[va]['Activator'] if va.downcase.include?(assistant.downcase) }
    nil
  end

  private
  def check_search(obj, search)
    return false if obj.nil?
    obj.include?(search)
  end
  
  def details_line(str)
    return '     none' if str.nil?
    '     ' << str.capitalize
  end
end
end
