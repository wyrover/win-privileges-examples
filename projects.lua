BOOK_CODE_PATH = "E:/book-code"
THIRD_PARTY = "E:/book-code/3rdparty"
WORK_PATH = os.getcwd()
includeexternal (BOOK_CODE_PATH .. "/premake-vs-include.lua")




workspace(path.getname(os.realpath(".")))
    language "C++"
    location "build/%{_ACTION}/%{wks.name}"    
    if _ACTION == "vs2015" then
        toolset "v140_xp"
    elseif _ACTION == "vs2013" then
        toolset "v120_xp"
    end

    include (BOOK_CODE_PATH .. "/common.lua")   
    

    group "test"       
        


        create_console_project("DumpProccessToken", "src")
            includedirs
            {
                "%{THIRD_PARTY}/doctest",                
                "%{THIRD_PARTY}",
            }
            links
            {
                --"gtest",
            }
            
        create_console_project("token", "src")
            includedirs
            {
                "%{THIRD_PARTY}/doctest",                
                "%{THIRD_PARTY}",
            }
            links
            {
                "Mpr.lib",
                "Netapi32.lib"
            }


        create_console_project("winutils", "src")
            defines { "_WIN32_WINNT=0x0600" }
            includedirs
            {
                "src/winutils/include",
                "%{THIRD_PARTY}/doctest",                
                "%{THIRD_PARTY}",
            }
            links
            {
                
                
            }
