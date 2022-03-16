#include <stddef.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include "gradient.h"

#ifdef printf
#undef printf
#endif

// The landscape matrix
static int landscape_width, landscape_height;
static float **matrix;
static int queries_made = 0;
static path_point user_path[1000];  // Array to store the path taken by the user
static path_point landscape_peak;

struct eval_result{
    float avg_success;
    float num_failures;
    int worst_success;
};

#define MIN_WIDTH   200
#define MIN_PEAK_HEIGHT     300
#define PERF_ITERS  1000
#define PERF_RATIO  10

/**
 * Add a peak centered on position x, y with given height.
 *
 * The peak stretches until the farthest corner of the matrix, where it starts at
 * altitude zero.
 */
void add_peak(float **matrix, int h, int w, int x, int y, int height){
    // First find the farthest corner from x and y
    float distance, tmp;
    float gradient;
    int i,j;

    // Store the peak position
    landscape_peak.x = x;
    landscape_peak.y = y;

    // Distance to top left (origin)
    distance = sqrt(x*x + y*y);

    // Distance to top right (y=0, x=w)
    tmp = sqrt((w-x)*(w-x)+y*y);
    if (tmp > distance) distance = tmp;

    // Distance to bottom right (x=w, y=h)
    tmp = sqrt((w-x)*(w-x)+(h-y)*(h-y));
    if (tmp > distance) distance = tmp;

    // Distance to bottom left (x=0, y=h)
    tmp = sqrt(x*x+(h-y)*(h-y));
    if (tmp > distance) distance = tmp;

    //printf("Max distance is %0.2f\n", distance);
    gradient = height/distance;
    //printf("Gradient is %0.2f\n", gradient);

    // Start filling in the level values
    for (i=0;i<h;i++){
        for (j=0;j<w;j++){
            // Calculate the distance between the location and the center
            distance = sqrt((x-j)*(x-j)+(y-i)*(y-i));
            // Calculate the altitude at i,j
            matrix[i][j] = height - distance*gradient;
        }
    }
}

/**
 * Adds noise to the landscape in the form of plateaus
 */
void add_noise(float **matrix, int height, int width, int number, int max_size){
    int i;

    for (i=0;i<number;i++){
        int center_x = max_size + random()%(width-max_size); // initial position
        int center_y = max_size + random()%(height-max_size);
        int x, y;
        int startx, starty, endx, endy;
        int radius = 1 + random()%(max_size-1); // at least 1 pixel radius
        int lower = random()%2; // the plateau can bring the terrain down or up
        float plateau_altitude;
        // Find the bounds of the plateau (must be within bounds of terrain)
        startx = center_x - radius;
        if (startx < 0) startx = 0;
        endx = center_x + radius;
        if (endx >= width) endx = width-1;
        starty = center_y - radius;
        if (starty < 0) starty = 0;
        endy = center_y + radius;
        if (endy >= height) endy = height-1;
        // The plateau should not contain the peak
        if (landscape_peak.x > startx && landscape_peak.x < endx
                && landscape_peak.y > starty 
                && landscape_peak.y < endy)
        {
            continue;
        }
        // Find the intended altitude of the plateau by going through
        // the matrix elements within the plateau area and finding min/max
        if (lower) plateau_altitude = 999999;
        else plateau_altitude = 0;
        for (y = starty; y < endy; y++){
            for (x = startx; x < endx; x++){
                // Only consider the elements within the plateau circle
                int distance = (center_x - x)*(center_x - x)
                             + (center_y - y)*(center_y - y);
                if (distance < radius*radius){
                    if (lower){
                        if (matrix[y][x] < plateau_altitude){
                            plateau_altitude = matrix[y][x];
                        }
                    }else{
                        if (matrix[y][x] > plateau_altitude){
                            plateau_altitude = matrix[y][x];
                        }
                    }
                }
            }
        }
        //printf("Adding plateau of height %0.2f at %d %d\n",
        //        plateau_altitude, center_x, center_y);
        // Set all the positions in the plateau to the plateau altitude
        for (y = starty; y < endy; y++){
            for (x = startx; x < endx; x++){
                // Only consider the elements within the plateau circle
                int distance = (center_x - x)*(center_x - x)
                             + (center_y - y)*(center_y - y);
                if (distance < radius*radius){
                    matrix[y][x] = plateau_altitude;
                }
            }
        }
    }
}

void generate_landscape(int seed){
    float *matrix_data;
    int i,j;

    if (seed > 0) srandom(seed);

    landscape_width = MIN_WIDTH + random()%MIN_WIDTH;
    landscape_height = MIN_WIDTH + random()%MIN_WIDTH;

    //printf("Matrix of size %dx%d\n", landscape_height, landscape_width);

    // Allocate memory for the landscape matrix
    // First allocate memory for the row pointers
    matrix = malloc(landscape_height*sizeof(float*));
    if (matrix == NULL){
        printf("Error allocating memory\n");
        return;
    }
    // Allocate memory contiguously for the matrix cells
    matrix_data = malloc(landscape_height*landscape_width*sizeof(float));
    // Point the matrix rows to the start of each cell row in the matrix data
    for (i=0;i<landscape_height;i++){
        matrix[i] = &matrix_data[i*landscape_width];
    }

    // Add a peak
    add_peak(matrix, landscape_height, landscape_width,
            random()%landscape_width, // peak x position
            random()%landscape_height, // peak y position
            MIN_PEAK_HEIGHT+(random()%MIN_PEAK_HEIGHT)); // peak height

    // Add noise as plateaus
    add_noise(matrix, landscape_height, landscape_width,
            40, // Number of plateaus to deploy
            15);// Max radius of plateau

}

void free_landscape(){
    free(matrix[0]); // Pointer to the matrix data
    free(matrix);
}

void print_matrix(){
    int i,j;
    // Print the matrix
    for (i=0;i<landscape_height;i++){
        for (j=0;j<landscape_width;j++){
            printf("%0.2f ", matrix[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

/**
 * This function generates a view of the matrix centered around center_y and_x.
 * Where the view goes out of matrix bounds it will take the value -1.
 */
void generate_view(float view[VIEW_SIZE][VIEW_SIZE], int center_y, int center_x){
    int matrix_start_x, matrix_start_y, matrix_end_x, matrix_end_y;
    int start_x, start_y, end_x, end_y;
    int i,j;

    if (queries_made > landscape_width*landscape_height) return; // TODO return an error
    user_path[queries_made].x = center_x;
    user_path[queries_made].y = center_y;
    queries_made++;

    // Init the view with -1 values
    for (i=0;i<VIEW_SIZE;i++)
        for (j=0;j<VIEW_SIZE;j++)
            view[i][j] = -1;

    // Find the boundaries of the view within the matrix
    start_x = start_y = 0;
    end_x = end_y = VIEW_SIZE;
    matrix_start_x = center_x - VIEW_RADIUS;
    if (matrix_start_x < 0){
        start_x = -matrix_start_x;
        matrix_start_x = 0;
    }
    matrix_start_y = center_y - VIEW_RADIUS;
    if (matrix_start_y < 0){
        start_y = -matrix_start_y;
        matrix_start_y = 0;
    }
    matrix_end_x = center_x + VIEW_RADIUS+1;
    if (matrix_end_x >= landscape_width){
        end_x = VIEW_SIZE - (matrix_end_x - landscape_width);
        matrix_end_x = landscape_width;
    }
    matrix_end_y = center_y + VIEW_RADIUS+1;
    if (matrix_end_y >= landscape_height){
        end_y = VIEW_SIZE - (matrix_end_y - landscape_height);
        matrix_end_y = landscape_height;
    }

    // Copy values into the view
    for (i=start_y;i<end_y;i++)
        for (j=start_x;j<end_x;j++)
            view[i][j] = matrix[matrix_end_y-end_y+i][matrix_end_x-end_x+j];
}

/**
 * This function declares that the peak has been found at position y,x.
 * The function will return true (1) if correct, false (0) otherwise.
 */
int declare_peak(int x, int y){
    if (queries_made > landscape_width*landscape_height) return 0; // TODO return an error
    queries_made ++;
    if (x == landscape_peak.x && y == landscape_peak.y) return 1;
    else return 0;
}

void print_view(float view[][VIEW_SIZE]){
    int i,j;
    for (i=0;i<VIEW_SIZE;i++){
        for (j=0;j<VIEW_SIZE;j++)
            printf("%0.2f ", view[i][j]);
        printf("\n");
    }
    printf("\n");
}

int single_run(int seed){
    path_point p;
    queries_made = 0;
    if (seed == -1){
        srandom(time(NULL)); // Seed PRNG with current time
    }
    generate_landscape(seed);
    p = find_highest_point();
    free_landscape();
    // Check if the point found matches the peak
    if (p.x == landscape_peak.x && p.y == landscape_peak.y)
        return queries_made;
    // If the peak was not found, return the maximum value
        return landscape_width*landscape_height;
}

struct eval_result performance_eval(){
    int i;
    //int results[1000];
    float success_sum = 0;
    int success_num = 0;
    int worst_success = 0;
    int failures = 0;
    path_point p;
    struct eval_result res;

    // Initialise PRNG for current time
    srandom(time(NULL));

    for (i=0;i<PERF_ITERS;i++){
        //srandom(i);
        queries_made = 0;
        generate_landscape(-1);
        p = find_highest_point();
        if (p.x != landscape_peak.x || p.y != landscape_peak.y){
            //queries_made = landscape_width*landscape_height;
            failures ++;
        }else{
            success_sum += queries_made;
            success_num ++;
            if (queries_made > worst_success) worst_success = queries_made;
        }
        free_landscape();
        //printf("Attempt %d peak at %d-%d, found in %d tries\n",
        //        i, landscape_peak.y, landscape_peak.x, queries_made);
    }

    res.avg_success = success_sum/success_num;
    res.num_failures = ((float)failures)/PERF_RATIO;
    res.worst_success = worst_success;

    return res;
}

void configure_seccomp() {
    struct sock_filter filter [] = {
        // Load the syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        // If it is equal to 
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_brk, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_munmap, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fstat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    // Configuring seccomp
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int main(){
    struct eval_result res;
    int i;

    alarm(60); // Interrupt the program after 60 seconds to prevent inf loop
    configure_seccomp();

    res = performance_eval();
    //print_matrix();
    //printf("Path taken: ");
    //for (i=0;i<queries_made;i++)
    //    printf("%d-%d ", user_path[i].y, user_path[i].x);
    //printf("\n");
    //printf("Peak at %d-%d\n", landscape_peak.y, landscape_peak.x);
    printf("%0.2f,%d,%0.2f\n", res.avg_success, res.worst_success, res.num_failures);

    return 0;
}
