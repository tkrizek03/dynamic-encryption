import os
import sys
import gpxpy
import gpxpy.gpx

from AirportRecord import AirportRecord


class GlobalAirportDatabase:
    
    '''
    CONSTRUCTOR - Initializes to an empty database
    '''
    def __init__( self ):
        self.airportRecords = {}
        self.countriesIndex = {}
            
            

    '''
    FUNCTION
        load - Loads an airport database in memory from a file with a very specific format.  The 
               GlobalAirportDatabase.readme.txt documents where this file came from and what it's 
               expected format is
               
    PARAMETERS
        The absolute or relative path to the flat file holding the database content
    
    RETURNS
        Returns the count of how many valid records were loaded into memory
        
    RAISES    
        Nothing intentionally
        
    SAMPLE CODE
        gdb = GlobalAirportDatabase()
        validCount, invalidCount = gdb.load( fileName )
        print( "Loaded %d valid airport records, and ignored %d invalid records" % ( validCount, invalidCount ) )
    '''
    def load( self, filePath ):
        invalidEntriesCount = 0
        for line in open( filePath ):
            line = line.strip()     # Remove newline characters
            items = line.split(':') # Split the line by ':' chars 
            try:
                IATACode    = items[1].strip()
                airportName = items[2]
                country     = items[4].strip()
                latitude    = float( items[14] )
                longitude   = float( items[15] )
                airportRec  = AirportRecord( IATACode, airportName, country, latitude, longitude )
                self.airportRecords[IATACode] = airportRec
                if country not in self.countriesIndex:
                    self.countriesIndex[country] = []
                self.countriesIndex[country].append(IATACode)
                
            except ValueError as v:
                invalidEntriesCount += 1
        return len(self.airportRecords), invalidEntriesCount
        


    '''
    FUNCTION
        lookup - Search the database for an airport by it's IATA code
    
    PARAMETERS    
        iata - The 3 character iata code of an airport to search for.  Example LAX
        
    RETURNS
        AirportRecord.AirportRecord() if one is found
        NONE otherwise
        
    CODE SAMPLE
        a = airportDB.lookup('lax')
        if a is not None:
            print( a.iata, a.country, a.name, a.lat, a.lon )
        else:
            print( "Not found" )            
    '''
    def lookup( self, iata ):
        if iata in self.airportRecords:
            return self.airportRecords[iata]
        return None
        
        
    
    '''
    FUNCTION
        valuesList - Return the whole database as an unsorted list that can be iterated
    
    PARAMETERS    
        None
        
    RETURNS
        A list of AirportRecord
        
    CODE SAMPLE
        for a in airportDB.valuesList():
            print( a.iata, a.country, a.name, a.lat, a.lon )
        
    '''
    def valuesList( self ):
        return self.airportRecords.values()
        


    '''
    FUNCTION
        valuesList - Return a unique unsorted list of all the countries that are listed in the database
    
    PARAMETERS    
        None
        
    RETURNS
        A list of country names
        
    CODE SAMPLE
        for cntry in airportDB.countries():
            print( cntry )        
    '''
    def countries( self ):
        return self.countriesIndex.keys()


    '''
    FUNCTION
        countryIATAList - Return a unique unsorted list of all IATA codes of airport in a given country
    
    PARAMETERS    
        Country - The name of the country to find IATA codes for 
        
    RETURNS
        A list of IATA codes 
        
    CODE SAMPLE
        for iata in airportDB.countryIATAList( "USA" ):
            a = airportDB.lookup( iata )
            print( a.iata, a.name, a.lat, a.lon )
    '''
    def countryIATAList( self, country ):
        return self.countriesIndex[country]




helpmsg = '''

    python GlobalAirportDatabase.py DBFileName 
    
'''
def help():
    print( helpmsg )
    sys.exit(1)

        
if __name__ == "__main__":
    if len(sys.argv) > 1:
        dbfile = sys.argv[1].strip()
        if not os.path.exists( dbfile ):
            print( "The supplied database file (%s) does not exist" % dbfile )
    else:
        help()        
    
    gdb = GlobalAirportDatabase()
    print()
    print( "Loading airports from %s" % sys.argv[1] )
    v, i = gdb.load( sys.argv[1] )    
    print( "    >  %d Airports loaded" % v )
    print( "    > %d entries ignored" % i )
    print()
    
    for country in gdb.countries():
        print()
        print( "-----------------------------------------------------------------------")
        print( country )
        print( "-----------------------------------------------------------------------")
        for iata in gdb.countryIATAList(country):           
           a = gdb.lookup(iata)
           print( "%3.3s %35.35s %12.6f %12.6f" % ( a.iata, a.name, a.lat, a.lon ) )
    print()       