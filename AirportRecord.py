import os
import sys
import gpxpy
import gpxpy.gpx

class AirportRecord:
    
    '''
    CONSTRUCTOR - Takes 
        iata - The 3 character airport IATA Code, such as LAX for Los Angeles International Airport
        name - The airport name such as "Los Angeles International"
        latitude - Decimal degrees
        longitude - Decimal degrees
        
    RAISES - 
        ValueError - if the ...
           IATA code is N/A
           AirportName is N/A
           The location is approximately (0.0, 0.0)

    SAMPLE CODE
        from AirportRecord import AirportRecord
        a = AirportRecord( 'MCI', 'KANSAS CITY INTERNATIONAL', 'USA', 39.297, -94.714 )
        print( a.iata, a.name, a.country, a.lat, a.lon )
    '''
    def __init__( self, iata, name, country, latitude, longitude ):
        self.iata = iata
        self.name = name
        self.country = country
        self.lat = latitude
        self.lon = longitude
        if iata == "N/A" : 
            raise ValueError("Received an invalid IATA code")
        if name == "N/A" : 
            raise ValueError("Received an invalid airport name")
        if (abs(latitude) < 0.001) and (abs(longitude) < 0.001): 
            raise ValueError("Received invalid airport coordinates ")
            
            
    